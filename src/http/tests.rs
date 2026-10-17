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
use std::net::{IpAddr, Ipv4Addr, TcpListener};
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
use super::{ErrorKind, HttpClient, HttpConnectionHandle, Result};

const SERVER_CERT: &[u8] = include_bytes!("testdata/server.der");
const SERVER_KEY: &[u8] = include_bytes!("testdata/server.key.der");
const OTHER_CERT: &[u8] = include_bytes!("testdata/other.der");

/// Serves one HTTPS request with a fixed "ok" body, returning the port.
fn https_server() -> u16 {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(SERVER_CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(SERVER_KEY.to_vec())),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return, // the client gave up on the handshake
                Ok(size) => request.extend_from_slice(&buf[..size]),
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = tls.flush();
    });

    port
}

/// Connects to `url` with `root` as the only trusted certificate, resolving
/// localhost without a DNS server.
fn connect(root: &[u8], url: &str) -> (Arc<Runtime>, Result<HttpConnectionHandle>) {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let rt = Arc::new(Runtime::new().unwrap());
    let dns_client = Arc::new(DnsClient::new(Arc::clone(&rt)));
    dns_client.cache_address("localhost", IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client = HttpClient::new(Arc::new(config), dns_client, Arc::clone(&rt));

    let url = Url::parse(url).unwrap();
    let result = rt.block_on(async {
        timeout(Duration::from_secs(10), client.connect(&url, false))
            .await
            .expect("connect timed out")
    });

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
        let (rt, result) = connect(SERVER_CERT, &format!("https://{}:{}/", host, port));
        let conn = result.ok().expect("connect failed");
        assert!(conn.cipher_id().is_some());
        get_ok(&rt, &conn, host);
    }
}

#[test]
fn untrusted_certificate_is_a_handshake_failure() {
    for host in ["127.0.0.1", "localhost"] {
        let port = https_server();
        let (_rt, result) = connect(OTHER_CERT, &format!("https://{}:{}/", host, port));
        assert!(is_handshake_failure(&result), "{} {:?}", host, result.err());
    }
}

#[test]
fn refused_connection_is_reported_for_ip_hosts() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let (_rt, result) = connect(SERVER_CERT, &format!("http://127.0.0.1:{}/", port));
    assert!(
        matches!(result, Err(ErrorKind::Stream(stream::ErrorKind::Io))),
        "{:?}",
        result.err()
    );
}
