#[allow(dead_code)]
mod bridge;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod frame;
mod server;
mod session;
#[allow(dead_code)]
mod token;

use std::net::SocketAddr;
use std::path::Path;

use tokio_util::sync::CancellationToken;

fn die(message: String) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args().skip(1);
    let mut config_path = "config.json".to_string();
    let mut profiles_override: Option<String> = None;
    let mut check = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-config" | "--config" => {
                config_path = arguments
                    .next()
                    .unwrap_or_else(|| die("--config requires a value".to_string()));
            }
            "-profiles-file" | "--profiles-file" => {
                profiles_override = Some(
                    arguments
                        .next()
                        .unwrap_or_else(|| die("--profiles-file requires a value".to_string())),
                );
            }
            "-check" | "--check" => check = true,
            other => die(format!("flag provided but not defined: {other}")),
        }
    }

    let mut value = config::load(
        Path::new(&config_path),
        profiles_override.as_deref().map(Path::new),
    )
    .unwrap_or_else(|error| die(format!("configuration error: {error}")));
    value.legacy_token_drain = std::env::var("TPROXY_LEGACY_TOKEN_DRAIN").as_deref() == Ok("1");
    session::validate_budget(&value.limits)
        .unwrap_or_else(|error| die(format!("configuration error: {error}")));
    let application = server::Server::new(value)
        .unwrap_or_else(|error| die(format!("server initialization error: {error}")));
    if check {
        println!("configuration is valid");
        return;
    }
    let config = application.config();
    let public_listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .unwrap_or_else(|error| die(format!("public listener error: {error}")));
    let admin_listener = tokio::net::TcpListener::bind(&config.admin_listen)
        .await
        .unwrap_or_else(|error| die(format!("admin listener error: {error}")));
    eprintln!(
        "event=started public={} admin={} profiles={} legacy_token_drain={}",
        config.listen,
        config.admin_listen,
        config.profiles.len(),
        config.legacy_token_drain,
    );

    let cancel = CancellationToken::new();
    let signal_task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            wait_for_signal().await;
            eprintln!("event=shutdown");
            cancel.cancel();
        }
    });
    let public_serve = axum::serve(
        public_listener,
        application
            .handler()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown({
        let cancel = cancel.clone();
        async move { cancel.cancelled().await }
    });
    let admin_serve = axum::serve(admin_listener, application.admin_handler())
        .with_graceful_shutdown({
            let cancel = cancel.clone();
            async move { cancel.cancelled().await }
        });
    let mut public_handle = tokio::spawn(public_serve.into_future());
    let mut admin_handle = tokio::spawn(admin_serve.into_future());
    tokio::select! {
        result = &mut public_handle => {
            eprintln!("event=listener_failed class=http");
            cancel.cancel();
            if result.is_err() {
                eprintln!("event=listener_join_error");
            }
        }
        result = &mut admin_handle => {
            eprintln!("event=listener_failed class=admin");
            cancel.cancel();
            if result.is_err() {
                eprintln!("event=listener_join_error");
            }
        }
        _ = cancel.cancelled() => {}
    }
    let shutdown_timeout = config.timeouts.shutdown.value();
    let _ = tokio::time::timeout(shutdown_timeout, &mut public_handle).await;
    let _ = tokio::time::timeout(shutdown_timeout, &mut admin_handle).await;
    public_handle.abort();
    admin_handle.abort();
    signal_task.abort();
    application.manager().shutdown().await;
    eprintln!("event=stopped");
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
