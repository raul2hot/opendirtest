//! A tiny HTTP/1.1 test server: fixed routes, a request log, and Range support.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[derive(Clone)]
pub struct Route {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Route {
    pub fn new(status: u16, content_type: Option<&str>, body: impl Into<Vec<u8>>) -> Self {
        let headers = content_type
            .map(|ct| vec![("Content-Type".to_string(), ct.to_string())])
            .unwrap_or_default();
        Self {
            status,
            headers,
            body: body.into(),
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::new(status, Some("text/plain"), body)
    }

    pub fn redirect(to: &str) -> Self {
        Self::new(301, Some("text/html"), "moved").header("Location", to)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// An nginx-style listing. Entries ending in `/` are directories.
pub fn listing(path: &str, entries: &[(&str, u64)]) -> Route {
    let mut body = format!(
        "<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1><hr><pre><a href=\"../\">../</a>\n"
    );
    for (name, size) in entries {
        let size = if name.ends_with('/') {
            "-".to_string()
        } else {
            size.to_string()
        };
        body.push_str(&format!(
            "<a href=\"{name}\">{name}</a>                28-Sep-2026 10:15                {size}\n"
        ));
    }
    body.push_str("</pre><hr></body></html>");
    Route::new(200, Some("text/html"), body)
}

pub struct Server {
    pub base: Url,
    /// Every requested path, in order.
    pub log: Arc<Mutex<Vec<String>>>,
    /// Body bytes sent, per path.
    pub sent: Arc<Mutex<HashMap<String, u64>>>,
}

impl Server {
    pub fn port(&self) -> u16 {
        self.base.port().unwrap()
    }

    pub fn requested(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// The same server under the name `localhost`, which the crawler treats
    /// as a different site from `127.0.0.1`.
    pub fn as_localhost(&self) -> Url {
        self.as_host("localhost")
    }

    /// The same server under another host name (`127.0.0.2`, `127.0.0.3`, ...),
    /// which the crawler treats as a different site.
    pub fn as_host(&self, host: &str) -> Url {
        Url::parse(&format!("http://{host}:{}/", self.port())).unwrap()
    }
}

pub async fn serve(routes: HashMap<String, Route>) -> Server {
    serve_with(Arc::new(move |path, _| {
        routes
            .get(path)
            .cloned()
            .unwrap_or_else(|| Route::text(404, "not found"))
    }))
    .await
}

/// Answers every request from `handler(path, n)`, `n` being the number of the
/// request (from 1, robots.txt included), for sites made up as they are asked for.
pub type Handler = Arc<dyn Fn(&str, u64) -> Route + Send + Sync>;

pub async fn serve_with(handler: Handler) -> Server {
    // All of 127.0.0.0/8 is loopback, so one server can play several "sites".
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(Mutex::new(HashMap::new()));
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (log2, sent2) = (log.clone(), sent.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (handler, log, sent, counter) = (
                handler.clone(),
                log2.clone(),
                sent2.clone(),
                counter.clone(),
            );
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&buf).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.lock().unwrap().push(path.clone());
                let range = request.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("range")
                        .then(|| value.trim().to_string())
                });

                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let route = handler(&path, n);
                let (status, extra, body) = match (&range, route.status) {
                    (Some(range), 200) => partial(range, &route.body),
                    _ => (route.status, None, route.body.clone()),
                };
                let mut head = format!("HTTP/1.1 {status} X\r\n");
                for (name, value) in &route.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                if let Some(content_range) = extra {
                    head.push_str(&format!("Content-Range: {content_range}\r\n"));
                }
                head.push_str(&format!(
                    "Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                ));
                if socket.write_all(head.as_bytes()).await.is_ok()
                    && socket.write_all(&body).await.is_ok()
                {
                    *sent.lock().unwrap().entry(path).or_default() += body.len() as u64;
                }
            });
        }
    });
    Server { base, log, sent }
}

/// Answers `bytes=a-b` and `bytes=-n` with 206 and the requested slice.
fn partial(range: &str, body: &[u8]) -> (u16, Option<String>, Vec<u8>) {
    let len = body.len() as u64;
    let spec = range.trim_start_matches("bytes=");
    let (start, end) = match spec.split_once('-') {
        Some(("", n)) => (len.saturating_sub(n.parse().unwrap_or(0)), len - 1),
        Some((a, "")) => (a.parse().unwrap_or(0), len - 1),
        Some((a, b)) => (
            a.parse().unwrap_or(0),
            b.parse::<u64>().unwrap_or(0).min(len - 1),
        ),
        None => return (416, None, Vec::new()),
    };
    let slice = body[start as usize..=end as usize].to_vec();
    (206, Some(format!("bytes {start}-{end}/{len}")), slice)
}

pub fn temp_db(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("opendirtest-{name}-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

pub fn query_one<T: rusqlite::types::FromSql>(db: &Path, sql: &str) -> T {
    opendirtest::store::open(db)
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}
