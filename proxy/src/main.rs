#![allow(unused_imports, unused_must_use)]

use std::{self, cell::RefCell, sync::Arc, thread, time::Duration};

use clap;
use env_logger;
use httparse;
use lazy_static::lazy_static;
use log::{debug, error, info};
use rand::Rng;
use serde;
use serde_json;
use tokio::{
    self, io,
    net::{
        self,
        tcp::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf},
    },
    time::timeout,
};

const OVERFLOWSIZE: usize = 1024 * 1024 * 50;
lazy_static! {}

#[tokio::main(worker_threads = 8)]
async fn main() {
    env_logger::init();

    let mut tasks = Vec::new();
    for i in 0..100 {
        let task = tokio::spawn(async move {
            let port = 8000 + i;
            let listener = net::TcpListener::bind(format!("0.0.0.0:{port}"))
                .await
                .unwrap();
            loop {
                let (mut stream, addr) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();

                    let raw_proxy_header = read_proxy_header(&r).await;
                    let (method, path) = extra_method_path(&raw_proxy_header);

                    let mut target = match method.to_uppercase().as_str() {
                        "CONNECT" => net::TcpStream::connect(path),
                        _ => {
                            let mut tmp = path.split('/').nth(2).unwrap();
                            let _path = match &tmp.contains(':') {
                                true => tmp.to_string(),
                                false => {
                                    let x = format!("{}:80", tmp);
                                    x
                                }
                            };
                            net::TcpStream::connect(_path)
                        }
                    };

                    // timeout !
                    let mut target = timeout(Duration::from_secs(2), target)
                        .await
                        .unwrap()
                        .unwrap();

                    let (mut tr, mut tw) = target.into_split();

                    if method.to_uppercase() == "CONNECT" {
                        &w.writable().await.unwrap();
                        &w.try_write("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes())
                            .unwrap();
                    }

                    //
                    tokio::spawn(async move {
                        //tr, w
                        r2w(&tr, &w, "读目标").await;
                    });
                    tokio::spawn(async move {
                        //r, tw
                        if method.to_uppercase() != "CONNECT" {
                            &tw.try_write(&raw_proxy_header);
                        }
                        r2w(&r, &tw, "写目标").await;
                    });
                });
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.unwrap();
    }
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

async fn read_proxy_header(r: &OwnedReadHalf) -> Vec<u8> {
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
    buffer
}

fn extra_method_path(raw_proxy_header: &Vec<u8>) -> (String, String) {
    let mut header = [httparse::EMPTY_HEADER; 4];
    let mut req = httparse::Request::new(&mut header);
    let res = req.parse(&raw_proxy_header.as_slice()).unwrap();
    debug!("{:?}", &req);

    (
        req.method.unwrap().to_string(),
        req.path.unwrap().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_test() {
        let mut stream = net::TcpStream::connect("www.qq.com:443").await.unwrap();
        tokio::spawn(async move {
            let (mut r, w) = stream.split();
            w.writable().await.unwrap();
            w.try_write("connect".as_bytes()).unwrap();

            let mut buffer = Vec::new();
            r.readable().await.unwrap();
            loop {
                let mut buff = [0; 1024];
                let n = match r.try_read(&mut buff) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 || buff.len() > OVERFLOWSIZE {
                    break;
                }
                buffer.extend_from_slice(&buff[..n]);
            }
            println!("what ? {}", std::str::from_utf8(&buffer).unwrap());
            //let size = r.read(&mut buff).unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn rt_test() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        for i in 0..100 {
            rt.spawn(async move {
                println!("hello from {}", i);
            });
        }
    }
}
