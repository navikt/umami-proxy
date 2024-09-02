use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use regex::{Regex, RegexBuilder};

const HOST: &str = "localhost";

#[derive(Serialize, Deserialize)]
pub struct Resp {
	ip: String,
}

pub struct Json2Yaml {
	addr: std::net::SocketAddr,
}

pub struct MyCtx {
	buffer: Vec<u8>,
}

// keep
const KEEP_REGEX: &str = r#"/(nav|test)[0-9]{6}"#;

// redact
const HEX_REGEX: &str = r#"/[a-f0-9\-]{6,}"#;
const ID_REGEX: &str = r#"/\d[oiA-Z0-9]{8,}"#;

#[derive(Debug, PartialEq, Eq)]
enum RedactType {
	RedactValue,
	Keep(String),
	Original(String),
}

impl RedactType {
	fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			RedactType::RedactValue => redacted.to_string(),
			RedactType::Keep(s) => s.to_string(),
			RedactType::Original(s) => s.to_string(),
		}
	}
}

fn redact(s: &str) -> RedactType {
	let original_string = s.into();
	// We "keep"
	let keepexe = Regex::new(KEEP_REGEX).expect("Unable to compile keepex regex");
	if let Some(foo) = keepexe
		.captures(original_string)
		.and_then(|m| m.get(0).map(|_| RedactType::Keep(s.to_string())))
	{
		return foo;
	};

	// We redact
	let hexexe = RegexBuilder::new(HEX_REGEX)
		.case_insensitive(true)
		.build()
		.expect("Unable to compile keepex regex");
	if let Some(foo) = hexexe
		.captures(original_string)
		.and_then(|m| m.get(0).map(|_| RedactType::RedactValue))
	{
		return foo;
	};
	let idexe = Regex::new(ID_REGEX).expect("Unable to compile keepex regex");
	if let Some(foo) = idexe
		.captures(original_string)
		.and_then(|m| m.get(0).map(|_| RedactType::RedactValue))
	{
		return foo;
	};

	RedactType::Original(original_string.to_string())
}

fn print_query((key, value): &(RedactType, RedactType)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<RedactType> {
	ps.iter().map(|p: &&str| redact(*p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(RedactType, RedactType)> {
	ss.iter().map(|q| (redact(q.0), redact(q.1))).collect()
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
		let redacted_paths = itertools::join(
			redact_paths(&upstream_request.uri.path().split("/").collect::<Vec<_>>())
				.iter()
				.map(RedactType::pretty_print),
			"/",
		);
		let redacted_queries = itertools::join(
			redact_queries(
				&upstream_request
					.uri
					.query()
					.unwrap_or("")
					.split("&")
					.map(|q| q.split_once("="))
					.flatten()
					.collect::<Vec<_>>(),
			)
			.iter()
			.map(print_query),
			"&",
		);
		dbg!(redacted_paths);
		dbg!(redacted_queries);
		unimplemented!()
		// upstream_request
		// 	.uri // TODO: set the path
		// 	.uri // TODO: set the query_params
		// 	.unwrap();
		// Ok(())
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
#[cfg(test)]
mod test {
	use super::*;
	#[test]
	fn test_nav() {
		let t = r#"/nav123456"#;
		assert_eq!(RedactType::Keep(t.to_string()), redact(t));
	}
	#[test]
	fn test_test() {
		let t = r#"/test123456"#;
		assert_eq!(RedactType::Keep(t.to_string()), redact(t));
	}
	#[test]
	fn test_hex() {
		let t = r#"/f6338366-64a5-44a7-8459-6cbf17a57343"#;
		assert_eq!(RedactType::RedactValue, redact(t));
	}
	#[test]
	fn test_id() {
		let t = r#"/12o798324i"#;
		assert_eq!(RedactType::RedactValue, redact(t));
	}
	#[test]
	fn test_norm() {
		let t = "quick brown fox jumped over the lazy dog";
		assert_eq!(RedactType::Original(t.to_string()), redact(t));
	}
}
