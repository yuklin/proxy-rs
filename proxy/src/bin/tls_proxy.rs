#![allow(unused_imports)]
use std::{
    env,
    fs::File,
    io::{stdout, BufReader, Read, Write},
    sync::Arc,
};

use argh::FromArgs;
use clap;
use env_logger;
use log::{debug, error, info, trace, warn};
use rustls::{
    server::{Acceptor, ServerConfig},
    Certificate, CipherSuite, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsStream};

#[derive(FromArgs, Debug)]
/// arg parser
struct Opt {
    /// crt file
    #[argh(option, short = 'c')]
    cert: Option<String>,

    /// key file
    #[argh(option, short = 'k')]
    key: Option<String>,

    /// port
    #[argh(option, short = 'p')]
    port: Option<u16>,
}

fn load_cert(filepath: String) -> Vec<rustls::Certificate> {
    certs(&mut BufReader::new(
        std::fs::File::open(&filepath).unwrap_or_else(|_| panic!("cannot open {}", filepath)),
    ))
    .map_err(|_| panic!("invalid cert {}", filepath))
    .map(|mut cert| cert.drain(..).map(Certificate).collect())
    .unwrap()
}

fn load_key(filepath: String) -> Vec<rustls::PrivateKey> {
    rsa_private_keys(&mut BufReader::new(
        std::fs::File::open(&filepath).unwrap_or_else(|_| panic!("cannot open {}", filepath)),
    ))
    .map_err(|_| panic!("invalid key {}", filepath))
    .map(|mut key| key.drain(..).map(PrivateKey).collect())
    .unwrap()
}

//fn gen_config() -> Arc<ServerConfig> {
//    let config = ServerConfig::builder()
//        .with_safe_defaults()
//        .with_no_client_auth();
//    Arc::new(config)
//}

#[tokio::main(worker_threads = 8)]
async fn main() {
    env_logger::init();
    let opt: Opt = argh::from_env();

    let port = opt.port.unwrap_or_else(|| 8000);
    let cert = load_cert(opt.cert.unwrap_or_else(|| "cert.pem".to_string()));
    let mut key = load_key(opt.key.unwrap_or_else(|| "cert.key".to_string()));
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key.remove(0))
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    loop {
        let (mut stream, addr) = listener.accept().await.unwrap();
        let raw_stream = stream.into_std().unwrap();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mock_stream = raw_stream.try_clone().unwrap();
            let mut proxy_stream = TcpStream::from_std(raw_stream).unwrap();

            let (mut rr, rw) = proxy_stream.split();

            //let (mut r, mut w) = stream.split();
            //todo 解析协议头
            let mut proxy_header_buf = [0u8; 1024];
            let n = rr.read(&mut proxy_header_buf).await.unwrap();
            println!(
                "代理协议\r\n-------------------------------\r\n{}",
                std::str::from_utf8(proxy_header_buf.as_slice()).unwrap()
            );

            &rw.writable().await.unwrap();
            &rw.try_write("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes())
                .unwrap();

            let tls_stream = acceptor
                .accept(TcpStream::from_std(mock_stream).unwrap())
                .await
                .unwrap();

            let (mut r, mut w) = split(tls_stream);

            let mut target_header_buf = [0u8; 1024];
            let n = &r.read(&mut target_header_buf).await.unwrap();

            println!(
                "https 协议 header & body\r\n-------------------------------\r\n{}",
                std::str::from_utf8(target_header_buf.as_slice()).unwrap()
            );

            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));

            let mut client_config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            let host = "tls.peet.ws:443";
            let raw_suites = "4865-4866-4867";
            let mut suites = Vec::new();
            for i in raw_suites.split('-') {
                suites.push(CipherSuite::from(i.parse::<u16>().unwrap()));
            }
            client_config.custom_cipher_suites = Some(suites);
            let mut conn = rustls::ClientConnection::new(
                Arc::new(client_config),
                "tls.peet.ws".try_into().unwrap(),
            )
            .unwrap();

            let mut target_stream = std::net::TcpStream::connect(host).unwrap();
            let mut tls_target_stream = rustls::Stream::new(&mut conn, &mut target_stream);

            tls_target_stream
                .write_all(
                    concat!(
                        "GET /api/all HTTP/1.1\r\n",
                        "HOST: tls.peet.ws\r\n",
                        "Connection: close\r\n",
                        "Accept: */*\r\n",
                        "User-Agent: curl/7.64.1\r\n",
                        "\r\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            let mut resp = Vec::new();
            tls_target_stream.read_to_end(&mut resp).unwrap();
            println!(
                "https 协议 resp\r\n-------------------------------\r\n{}",
                std::str::from_utf8(resp.as_slice()).unwrap()
            );
            w.write_all(resp.as_slice()).await.unwrap();
        });
    }
}
