use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use sha2::Digest;

pub(crate) struct StaticEntry {
    pub(crate) body: Vec<u8>,
    pub(crate) content_type: String,
    pub(crate) mod_time: SystemTime,
    pub(crate) etag: String,
}

pub(crate) struct StaticSite {
    entries: HashMap<String, Arc<StaticEntry>>,
    pub(crate) index: Arc<StaticEntry>,
    pub(crate) not_found: Arc<StaticEntry>,
}

impl StaticSite {
    pub(crate) fn load(root: &Path) -> std::io::Result<StaticSite> {
        let mut entries = HashMap::new();
        load_dir(root, root, &mut entries)?;
        let Some(index) = entries.get("/index.html").cloned() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "public site must contain index.html",
            ));
        };
        let not_found = entries
            .get("/404.html")
            .cloned()
            .unwrap_or_else(|| index.clone());
        Ok(Self {
            entries,
            index,
            not_found,
        })
    }

    pub(crate) fn resolve(
        &self,
        request_path: &str,
        legacy_routes: bool,
    ) -> Option<Arc<StaticEntry>> {
        if request_path.is_empty() || !request_path.starts_with('/') {
            return None;
        }
        if clean_url_path(request_path) != request_path || request_path.contains('\\') {
            return None;
        }
        if let Some(entry) = self.entries.get(request_path) {
            return Some(entry.clone());
        }
        if !legacy_routes {
            return None;
        }
        if request_path == "/favicon.ico" {
            return self.entries.get("/favicon.svg").cloned();
        }
        if url_ext(request_path).is_empty() {
            return self.entries.get(&format!("{request_path}.html")).cloned();
        }
        None
    }
}

fn load_dir(
    root: &Path,
    dir: &Path,
    entries: &mut HashMap<String, Arc<StaticEntry>>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            load_dir(root, &path, entries)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative == "." || relative.starts_with("../") {
            continue;
        }
        let data = std::fs::read(&path)?;
        let mod_time = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let etag = format!("\"{}\"", hex_lower(&sha2::Sha256::digest(&data)));
        entries.insert(
            format!("/{relative}"),
            Arc::new(StaticEntry {
                content_type: content_type_for(&relative),
                body: data,
                mod_time,
                etag,
            }),
        );
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn clean_url_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|last| *last != "..") {
                    stack.pop();
                } else if !rooted {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn url_ext(path: &str) -> &str {
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rfind('.') {
        Some(index) => &last[index..],
        None => "",
    }
}

fn content_type_for(relative: &str) -> String {
    let extension = url_ext(relative);
    let value = match extension {
        ".html" | ".htm" => "text/html; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".ico" => "image/vnd.microsoft.icon",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".json" => "application/json",
        ".txt" => "text/plain; charset=utf-8",
        ".xml" => "text/xml; charset=utf-8",
        ".pdf" => "application/pdf",
        ".woff" => "font/woff",
        ".woff2" => "font/woff2",
        ".webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_site_loads_whole_tree() {
        let directory = std::env::temp_dir().join(format!(
            "tproxy-site-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(directory.join("assets")).unwrap();
        std::fs::write(directory.join("index.html"), b"index").unwrap();
        std::fs::write(directory.join("assets").join("app.css"), b"body{}").unwrap();
        let site = StaticSite::load(&directory).unwrap();
        assert!(site.resolve("/assets/app.css", true).is_some());
        assert!(site.resolve("/assets/../index.html", true).is_none());
        assert!(site.resolve("/index", true).is_some());
        assert!(site.resolve("/", true).is_none());
        assert!(Arc::ptr_eq(&site.not_found, &site.index));
        std::fs::remove_dir_all(&directory).ok();
    }
}
