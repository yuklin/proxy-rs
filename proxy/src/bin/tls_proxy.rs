#![allow(unused_imports)]
use std::{
    env,
    fs::File,
    io::{stdout, BufReader, Read, Write},
    sync::Arc,
    time::Duration,
    vec,
};

use argh::FromArgs;
use bstr::{BStr, BString, ByteSlice, Bytes, Split, B};
use env_logger;
use format_bytes::format_bytes;
use log::{debug, error, info, trace, warn};
use rustls::{
    server::{Acceptor, ServerConfig},
    Certificate, CipherSuite, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{self, split, AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsStream};

use proxy::cipher::Table;

const OVERFLOWSIZE: usize = 1024 * 1024 * 50;

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

    /// fingerprints
    #[argh(option, short = 'f')]
    fp: Option<String>,

    /// redirect
    #[argh(option, short = 'r')]
    redir: Option<String>,

    /// passwd
    #[argh(option, short = 'w')]
    passwd: Option<String>,
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

#[derive(Debug)]
struct ProxyProtocol {
    https: bool,
    target: String,
    body: Vec<u8>,
    header: Vec<u8>,
}

async fn read_proxy_header<'a>(r: &ReadHalf<'a>) -> BString {
    let mut buffer = Vec::new();
    r.readable().await.unwrap();
    loop {
        // wtf vec就不行, 也不报错
        let mut buff = [0; 512];
        let n = match r.try_read(&mut buff) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 || buff.len() > OVERFLOWSIZE {
            break;
        }
        buffer.extend_from_slice(&buff[..n]);
    }
    debug!("{} bytes {:?}", &buffer.len(), &buffer);
    BString::from(buffer)
}

fn parse_proxy_header(header_buff: &BString) -> ProxyProtocol {
    let mut header = vec![];
    let mut body = vec![];
    let mut https = false;
    let mut target = String::new();
    let mut proxy = String::new();
    if header_buff.starts_with(b"CONNECT") {
        https = true;
    }

    if https {
        let tmp = header_buff.split(|char| *char == b' ').nth(1).unwrap();
        target = std::str::from_utf8(tmp).unwrap().to_string();
    } else {
        let tmp: Vec<&[u8]> = header_buff.split_str("\r\n").collect();
        // get target
        //
        //
        let mut buff = Vec::new();
        for i in tmp {
            if i.starts_with(b"Host:") {
                target = std::str::from_utf8(&i[6..]).unwrap().to_string();
                if target.find(':').is_none() {
                    target.push_str(":80");
                }
            }
            // Proxy is used
            if i.starts_with(b"WTF-Proxy:") {
                proxy = std::str::from_utf8(&i[11..]).unwrap().to_string();
                continue;
            }

            buff.push(BString::from(i));
        }

        let merge = bstr::join("\r\n", buff);
        let header_body = &merge.splitn_str(2, "\r\n\r\n").collect::<Vec<&[u8]>>();
        header.append(&mut header_body[0].to_vec());
        body.append(&mut header_body[1].to_vec());
    }

    ProxyProtocol {
        https: https,
        target: target,
        body: body,
        header: header,
    }

    //    loop {
    //        let mut line = Vec::new();
    //        let n = match header_buff.iter().position(|&x| x == b'\n') {
    //            Some(n) => n,
    //            None => break,
    //        };
    //        line.extend_from_slice(&header_buff[..n]);
    //        header_buff = &header_buff[n + 1..];
    //        if line.len() == 0 {
    //            break;
    //        }
    //        if line[0] == b'P' {
    //            let mut line = line.split(|&x| x == b' ');
    //            let _ = line.next();
    //            let mut line = line.next().unwrap().split(|&x| x == b':');
    //            let _ = line.next();
    //            let port = line.next().unwrap();
    //            if port == b"443" {
    //                https = true;
    //            }
    //        }
    //        header.push(line);
    //    }
    //    body.extend_from_slice(header_buff);
    //    ProxyProtocol {
    //        https,
    //        body,
    //        header: header
    //            .iter()
    //            .map(|x| {
    //                let mut line = x.split(|&x| x == b':');
    //                let key = line.next().unwrap().to_vec();
    //                let value = line.next().unwrap().to_vec();
    //                (key, value)
    //            })
    //            .collect(),
    //    }
}

async fn r2w(r: &OwnedReadHalf, w: &OwnedWriteHalf, flag: &str) {
    loop {
        r.readable().await.unwrap();
        let mut buff = [0; 2048];
        let n = match r.try_read(&mut buff) {
            Ok(n) => n,
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {
                    debug!("{} read would block", &flag);
                    continue;
                }
                _ => {
                    debug!("{} read error: {:?}", &flag, &e);
                    break;
                }
            },
        };
        debug!("{} read {} bytes, lets write", &flag, &n);
        if n == 0 {
            break;
        }
        w.writable().await.unwrap();
        w.try_write(&buff[0..n]).unwrap();
    }
}

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

    let fp = opt.fp.unwrap_or_else(|| String::from("")).clone();

    let redir = opt
        .redir
        .unwrap_or_else(|| String::from("127.0.0.1:5001"))
        .clone();
    let passwd = opt
        .passwd
        .unwrap_or_else(|| String::from("hehe123"))
        .clone();

    let Some((raw_suites, exts)) = fp.split_once(",") else {
        panic!("fp format error")
    };
    let raw_suites = raw_suites.to_string();
    let exts = exts.to_string();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();

    let mut ss_cipher = Table {
        key: passwd,
        ..Default::default()
    };

    ss_cipher.setup();

    let mut ss_cipher = Arc::new(ss_cipher);

    loop {
        let (mut stream, addr) = listener.accept().await.unwrap();
        let raw_stream = stream.into_std().unwrap();
        let acceptor = acceptor.clone();
        let raw_suites = raw_suites.clone();
        let exts = exts.clone();
        let ss_cipher = ss_cipher.clone();
        let redir = redir.clone();
        tokio::spawn(async move {
            let mock_stream = raw_stream.try_clone().unwrap();
            let mut proxy_stream = TcpStream::from_std(raw_stream).unwrap();

            let (mut rr, rw) = proxy_stream.split();

            let mut proxy_protocol_header = read_proxy_header(&rr).await;
            let proxy_protocol = parse_proxy_header(&proxy_protocol_header);

            if proxy_protocol.https {
                println!(
                    "代理协议\r\n-------------------------------\r\n{}",
                    std::str::from_utf8(&proxy_protocol_header.as_slice()).unwrap()
                );

                &rw.writable().await.unwrap();
                &rw.try_write("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes())
                    .unwrap();

                let tls_stream = acceptor
                    .accept(TcpStream::from_std(mock_stream).unwrap())
                    .await
                    .unwrap();

                let (mut r, mut w) = split(tls_stream);

                let mut root_cert_store = RootCertStore::empty();
                root_cert_store.add_server_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }),
                );

                let mut client_config = rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();

                let target = proxy_protocol.target;
                dbg!(&target);
                let mut host = String::new();
                let mut port = 443;

                match target.find(':') {
                    None => host = target.clone(),
                    Some(n) => {
                        host = target[..n].to_string();
                        port = target[n + 1..].parse::<u16>().unwrap();
                    }
                }

                let mut suites = Vec::new();
                for i in raw_suites.split('-') {
                    suites.push(CipherSuite::from(i.parse::<u16>().unwrap()));
                }
                client_config.custom_cipher_suites = Some(suites);
                // we can not use alpn
                //client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                client_config.alpn_protocols = Vec::new();

                client_config.custom_extensions = Some(exts.to_string());

                let conn = tokio_rustls::TlsConnector::from(Arc::new(client_config));

                // target now is a ss proxy
                //let mut target_stream = tokio::net::TcpStream::connect(target);
                let mut target_stream = tokio::net::TcpStream::connect(redir);

                // i can not modify client hello data, so use this pair to get data change data
                // write data
                let (hook_stream_in, mut hook_stream_out) = tokio::net::UnixStream::pair().unwrap();
                let mut target_tcp_stream = timeout(Duration::from_secs(3), target_stream)
                    .await
                    .unwrap()
                    .unwrap();

                let mut ss_header: Vec<u8> = Vec::new();
                ss_header.push(0x03);
                ss_header.push(host.len() as u8);
                ss_header.append(host.clone().into_bytes().as_mut());
                ss_header.append(port.to_be_bytes().to_vec().as_mut());

                let ss_header = ss_cipher.encrypt(&mut ss_header);

                let de_cipher = ss_cipher.clone();

                target_tcp_stream.write(ss_header.as_slice()).await.unwrap();

                let (mut target_tcp_read, mut target_tcp_write) = target_tcp_stream.into_split();
                let (mut hook_read, mut hook_write) = hook_stream_out.into_split();

                tokio::spawn(async move {
                    loop {
                        let mut buff: Vec<u8> = Vec::with_capacity(1024);
                        hook_read.readable().await.unwrap();
                        let n = hook_read.read_buf(&mut buff).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        let buff = ss_cipher.encrypt(&mut buff);
                        target_tcp_write.writable().await.unwrap();
                        target_tcp_write.write(buff.as_slice()).await.unwrap();
                    }
                });

                tokio::spawn(async move {
                    loop {
                        let mut buff: Vec<u8> = Vec::with_capacity(1024);
                        target_tcp_read.readable().await.unwrap();
                        let n = target_tcp_read.read_buf(&mut buff).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        let buff = de_cipher.decrypt(&mut buff);
                        hook_write.writable().await.unwrap();
                        hook_write.write(buff.as_slice()).await.unwrap();
                    }
                });

                let target_stream = conn
                    .connect(host.as_str().try_into().unwrap(), hook_stream_in)
                    .await
                    .unwrap();

                let (mut tr, mut tw) = split(target_stream);

                tokio::spawn(async move {
                    let buf = io::copy(&mut r, &mut tw).await.unwrap();
                });
                tokio::spawn(async move {
                    io::copy(&mut tr, &mut w).await.unwrap();
                });
            }
        });
    }
}
