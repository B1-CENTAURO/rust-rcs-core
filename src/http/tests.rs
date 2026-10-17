// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// testdata holds two self-signed P-256 certificates for localhost and
// 127.0.0.1, valid for 100 years:
//
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
//     -days 36500 -subj "/CN=localhost" \
//     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
//     -addext "basicConstraints=critical,CA:FALSE" -keyout key.pem -out cert.pem
//   openssl x509 -in cert.pem -outform DER -out server.der
//   openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out server.key.der
//
// other.der is made the same way with "/CN=other"; it is the root of a client
// that must reject the server.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::sync::Arc;
use std::thread;

use futures::AsyncReadExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use tokio::runtime::Runtime;
use tokio::time::{timeout, Duration};
use url::Url;

use crate::dns::DnsClient;
use crate::io::network::stream;

use super::request::{Request, GET};
use super::{ipv4_first, ErrorKind, HttpClient, HttpConnectionHandle, Result};

const SERVER_CERT: &[u8] = include_bytes!("testdata/server.der");
const SERVER_KEY: &[u8] = include_bytes!("testdata/server.key.der");
const OTHER_CERT: &[u8] = include_bytes!("testdata/other.der");

const V4_LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6_LOCALHOST: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn server_config() -> Arc<ServerConfig> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(SERVER_CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(SERVER_KEY.to_vec())),
        )
        .unwrap();
    Arc::new(config)
}

/// Answers one request with a fixed "ok" body.
fn serve(stream: &mut (impl Read + Write)) {
    let mut request = Vec::new();
    let mut buf = [0; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return, // e.g. the client gave up on the handshake
            Ok(size) => request.extend_from_slice(&buf[..size]),
        }
    }
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let _ = stream.flush();
}

/// Serves one HTTPS request, returning the port.
fn https_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config()).unwrap();
        serve(&mut StreamOwned::new(conn, socket));
    });

    port
}

/// Serves one plain HTTP request and then, on a second connection to the
/// same port, one HTTPS request, returning the port.
fn http_then_https_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        // kept open, so the client could reuse it
        let (mut plain, _) = listener.accept().unwrap();
        serve(&mut plain);

        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config()).unwrap();
        serve(&mut StreamOwned::new(conn, socket));
    });

    port
}

/// A client with `root` as the only trusted certificate, resolving localhost
/// to `localhost` without a DNS server.
fn client(root: &[u8], localhost: &[IpAddr]) -> (Arc<Runtime>, HttpClient) {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let rt = Arc::new(Runtime::new().unwrap());
    let dns_client = Arc::new(DnsClient::new(Arc::clone(&rt)));
    for ip in localhost {
        dns_client.cache_address("localhost", *ip);
    }
    let client = HttpClient::new(Arc::new(config), dns_client, Arc::clone(&rt));

    (rt, client)
}

fn connect(rt: &Runtime, client: &HttpClient, url: &str) -> Result<HttpConnectionHandle> {
    let url = Url::parse(url).unwrap();
    rt.block_on(async {
        timeout(Duration::from_secs(10), client.connect(&url, false))
            .await
            .expect("connect timed out")
    })
}

/// Connects to `url` with a new client, see `client()`.
fn connect_once(root: &[u8], url: &str) -> (Arc<Runtime>, Result<HttpConnectionHandle>) {
    let (rt, client) = client(root, &[V4_LOCALHOST]);
    let result = connect(&rt, &client, url);
    (rt, result)
}

fn get_ok(rt: &Runtime, conn: &HttpConnectionHandle, host: &str) {
    rt.block_on(async {
        let request = Request::new_with_default_headers(GET, host, "/", None);
        let (resp, body) = timeout(Duration::from_secs(10), conn.send(request, |_| {}))
            .await
            .expect("request timed out")
            .ok()
            .expect("request failed");
        assert_eq!(resp.status_code, 200);

        let mut data = Vec::new();
        body.unwrap().read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"ok");
    });
}

fn is_handshake_failure(result: &Result<HttpConnectionHandle>) -> bool {
    matches!(
        result,
        Err(ErrorKind::Stream(stream::ErrorKind::HandshakeFailure))
    )
}

#[test]
fn https_to_trusted_server() {
    for host in ["127.0.0.1", "localhost"] {
        let port = https_server();
        let (rt, result) = connect_once(SERVER_CERT, &format!("https://{}:{}/", host, port));
        let conn = result.ok().expect("connect failed");
        assert!(conn.cipher_id().is_some());
        get_ok(&rt, &conn, host);
    }
}

#[test]
fn untrusted_certificate_is_a_handshake_failure() {
    for host in ["127.0.0.1", "localhost"] {
        let port = https_server();
        let (_rt, result) = connect_once(OTHER_CERT, &format!("https://{}:{}/", host, port));
        assert!(is_handshake_failure(&result), "{} {:?}", host, result.err());
    }
}

fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn refused_connection_is_reported_for_ip_hosts() {
    let port = unused_port();
    let (_rt, result) = connect_once(SERVER_CERT, &format!("http://127.0.0.1:{}/", port));
    assert!(
        matches!(result, Err(ErrorKind::Stream(stream::ErrorKind::Io))),
        "{:?}",
        result.err()
    );
}

#[test]
fn ipv6_addresses_are_tried() {
    // refused, or unsupported where the host has no IPv6, but not skipped,
    // which would leave nothing to try and report Dns
    let (rt, client) = client(SERVER_CERT, &[V6_LOCALHOST]);
    let result = connect(
        &rt,
        &client,
        &format!("http://localhost:{}/", unused_port()),
    );
    assert!(
        matches!(result, Err(ErrorKind::Stream(stream::ErrorKind::Io))),
        "{:?}",
        result.err()
    );
}

#[test]
fn ipv4_addresses_are_tried_first() {
    let v4 = |n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n));
    let v6 = |n| IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n));
    let mut addresses = [v6(1), v4(1), v6(2), v4(2)];
    ipv4_first(&mut addresses);
    assert_eq!(addresses, [v4(1), v4(2), v6(1), v6(2)]);
}

#[test]
fn https_does_not_reuse_a_plain_connection() {
    let port = http_then_https_server();
    let (rt, client) = client(SERVER_CERT, &[V4_LOCALHOST]);

    let plain = connect(&rt, &client, &format!("http://localhost:{}/", port))
        .ok()
        .expect("connect failed");
    assert!(plain.cipher_id().is_none());
    get_ok(&rt, &plain, "localhost");

    let tls = connect(&rt, &client, &format!("https://localhost:{}/", port))
        .ok()
        .expect("connect failed");
    assert!(tls.cipher_id().is_some());
    get_ok(&rt, &tls, "localhost");
}

/// Serves one HTTPS request with `alpn` as the server's protocols, in order of
/// preference, returning the port and what the handshake settled on.
fn https_server_with_alpn(alpn: &[&[u8]]) -> (u16, std::sync::mpsc::Receiver<Option<Vec<u8>>>) {
    let mut config = ServerConfig::clone(&server_config());
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();

    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        serve(&mut tls);
        let _ = tx.send(tls.conn.alpn_protocol().map(|protocol| protocol.to_vec()));
    });

    (port, rx)
}

#[test]
fn https_offers_only_http_1_1() {
    // a config shared with something that speaks HTTP/2
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(SERVER_CERT.to_vec()))
        .unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let rt = Arc::new(Runtime::new().unwrap());
    let dns_client = Arc::new(DnsClient::new(Arc::clone(&rt)));
    let client = HttpClient::new(Arc::clone(&config), dns_client, Arc::clone(&rt));

    // the server would rather speak HTTP/2
    let (port, negotiated) = https_server_with_alpn(&[b"h2", b"http/1.1"]);
    let conn = connect(&rt, &client, &format!("https://127.0.0.1:{}/", port))
        .ok()
        .expect("connect failed");
    get_ok(&rt, &conn, "127.0.0.1");

    assert_eq!(
        negotiated.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(b"http/1.1".to_vec())
    );
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "the shared config is left as it was"
    );
}
