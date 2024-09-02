use async_trait::async_trait;
use bytes::Bytes;
use clap::clap_derive::Parser;
use pingora::{protocols::ssl, tls::ssl_sys::NID_host, upstreams};
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use url::Url;
use regex::Regex;

const HOST: &str = "localhost";

#[derive(Serialize, Deserialize)]
pub struct Resp {
	ip: String,
}

pub struct Json2Yaml {
	addr: std::net::SocketAddr,
}

#[derive(Debug)]
pub enum Redact {
	Redact(String),
	Keep(String),
	Original(String),
}

pub struct MyCtx {
	buffer: Vec<u8>,
}

// keep
const keepex: &str =  r#"/(nav|test)[0-9]{6}/g"#;

// redact
const hexex: &str = r#"/[a-f0-9\-]{6,}/gi"#;
const idex: &str = r#"/\d[oiA-Z0-9]{8,}/g"#;


pub fn redact(s: &str) -> Redact {
    let keepexe = Regex::new(keepex).unwrap();
    let hexexe = Regex::new(hexex).unwrap();
    let idexe = Regex::new(idex).unwrap();

    let reskeepexe = keepexe.captures(s).unwrap().get(0);
    if let foo = reskeepexe.map(|x| Redact::Keep(x.as_str().to_string()));

}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn testNavex() {}
}


#[async_trait]
impl ProxyHttp for Json2Yaml {
	type CTX = MyCtx;
	fn new_ctx(&self) -> Self::CTX {
		MyCtx { buffer: vec![] }
	}

	// This guy should be the amplitude host, all requests through the proxy gets sent th upstream_peer
	async fn upstream_peer(
		&self,
		_session: &mut Session,
		_ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		let peer = Box::new(HttpPeer::new(self.addr, false, HOST.to_owned()));
		Ok(peer)
	}

	//
	async fn upstream_request_filter(
		&self,
		_session: &mut Session,
		upstream_request: &mut pingora_http::RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		let redacted = "REDACTED";

		upstream_request
			.insert_header("Host", HOST.to_owned())
			.unwrap();
		let path = upstream_request.uri.path();
		// V skip(1) here is to avoid a ["", "PATH1", "PATH2" ... ]
		let path_parts: Vec<_> = path.split("/").skip(1).collect();
		let query = &upstream_request.uri.query();
		let query_parts: Vec<_> = query
			.unwrap_or("")
			.split("&")
			.map(|x| x.split_once("="))
		    .collect();

            let queryBits = path_parts.

		dbg!(path_parts);
		dbg!(query_parts);
		upstream_request
			.insert_header(
				"foo",
				format!("{:?} - {}", path.to_owned(), query.unwrap_or("no queries")),
			)
			.unwrap();
		Ok(())
	}

	async fn response_filter(
		&self,
		_session: &mut Session,
		upstream_response: &mut ResponseHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()>
	where
		Self::CTX: Send + Sync,
	{
		// Remove content-length because the size of the new body is unknown
		upstream_response.remove_header("Content-Length");
		upstream_response
			.insert_header("Transfer-Encoding", "Chunked")
			.unwrap();
		Ok(())
	}

	fn response_body_filter(
		&self,
		_session: &mut Session,
		body: &mut Option<Bytes>,
		end_of_stream: bool,
		ctx: &mut Self::CTX,
	) -> Result<Option<std::time::Duration>>
	where
		Self::CTX: Send + Sync,
	{
		// buffer the data
		if let Some(b) = body {
			ctx.buffer.extend(&b[..]);
			// drop the body
			b.clear();
		}
		if end_of_stream {
			// This is the last chunk, we can process the data now
			let json_body: Resp = serde_json::de::from_slice(&ctx.buffer).unwrap();
			let yaml_body = serde_yaml::to_string(&json_body).unwrap();
			*body = Some(Bytes::copy_from_slice(yaml_body.as_bytes()));
		}

		Ok(None)
	}
}
// RUST_LOG=INFO cargo run --example modify_response
// curl 127.0.0.1:6191
fn main() {
	env_logger::init();
	let mut my_server = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: None,
	}))
	.unwrap();
	my_server.bootstrap();

	let mut my_proxy = pingora_proxy::http_proxy_service(
		&my_server.configuration,
		Json2Yaml {
			// hardcode socat-echno socat -v tcp-l:1234,fork exec:'/bin/cat'
			addr: ("127.0.0.1", 1234)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
		},
	);

	my_proxy.add_tcp("127.0.0.1:6191");

	my_server.add_service(my_proxy);
	my_server.run_forever();
}
