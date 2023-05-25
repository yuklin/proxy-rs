#![allow(unused_imports)]
use std::{
    env,
    fs::File,
    io::{stdout, BufReader, Read, Write},
    sync::Arc,
    vec,
};

use argh::FromArgs;
use bstr::{BStr, BString, ByteSlice, Bytes, Split, B};
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
        tcp::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsStream};

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

fn splite_bs(buff: &Vec<u8>) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    let mut start = 0;
    //for i in 0..buff.len() {
    //    if buff[i] == b'\n' {
    //        res.push(buff[start..i].to_vec());
    //        start = i + 1;
    //    }
    //}
    res
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

            //let mut proxy_header_buf = [0u8; 1024];
            //let n = rr.read(&mut proxy_header_buf).await.unwrap();

            //let mut proxy_protocol_header = Vec::new();
            //let n = rr.read_to_end(&mut proxy_protocol_header).await.unwrap();
            //
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

                let mut target_header_buf = Vec::new();
                loop {
                    // wtf vec就不行, 也不报错
                    let mut buff = [0; 1024];
                    let n = match r.read(&mut buff).await {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    println!("{}", n);
                    target_header_buf.extend_from_slice(&buff[..n]);
                    if n == 0 || buff.len() > OVERFLOWSIZE || n < 1024 {
                        break;
                    }
                }
                dbg!(&target_header_buf);

                //let mut target_header_buf = [0u8; 1024];
                //let n = &r.read(&mut target_header_buf).await.unwrap();

                //let target_header_buf = &target_header_buf[..n].into();

                println!(
                    "https 协议 header & body\r\n-------------------------------\r\n{}",
                    std::str::from_utf8(target_header_buf.as_slice()).unwrap()
                );

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

                match target.find(':') {
                    None => host = target.clone(),
                    Some(n) => host = target[..n].to_string(),
                }
                dbg!(&host);

                let raw_suites = "4865-4866-4867";
                let mut suites = Vec::new();
                for i in raw_suites.split('-') {
                    suites.push(CipherSuite::from(i.parse::<u16>().unwrap()));
                }
                //client_config.custom_cipher_suites = Some(suites);
                let mut conn = rustls::ClientConnection::new(
                    Arc::new(client_config),
                    host.as_str().try_into().unwrap(),
                )
                .unwrap();

                let mut target_stream = std::net::TcpStream::connect(target).unwrap();
                let mut tls_target_stream = rustls::Stream::new(&mut conn, &mut target_stream);

                // todo!
                // use tokio copy later

                tls_target_stream
                    .write_all(target_header_buf.as_slice())
                    .unwrap();
                //let mut resp = [0; 1024];
                //tls_target_stream.read(&mut resp).unwrap();
                let mut resp = Vec::new();

                loop {
                    // wtf vec就不行, 也不报错
                    let mut buff = [0; 1024];
                    let n = match tls_target_stream.read(&mut buff) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    println!("{}", n);
                    resp.extend_from_slice(&buff[..n]);
                    if n == 0 || buff.len() > OVERFLOWSIZE || n < 1024 {
                        break;
                    }
                }

                println!(
                    "https 协议 resp\r\n-------------------------------\r\n{}",
                    std::str::from_utf8(resp.as_slice()).unwrap()
                );
                w.write_all(resp.as_slice()).await.unwrap();
                w.flush().await.unwrap();
            }
        });
    }
}
