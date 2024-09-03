use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::{Method, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};

use crate::redact::{print_query, redact_paths, redact_queries};

pub const HOST: &str = "localhost";

#[derive(Serialize, Deserialize)]
pub struct Resp {
	ip: String,
}

pub struct Addr {
	pub addr: std::net::SocketAddr,
}

pub struct Ctx {
	buffer: Vec<u8>,
}

#[async_trait]
impl ProxyHttp for Addr {
	type CTX = Ctx;
	fn new_ctx(&self) -> Self::CTX {
		Ctx { buffer: vec![] }
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
		session: &mut Session,
		upstream_request: &mut pingora_http::RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		dbg!(session.request_summary());
		let redacted_paths = itertools::join(
			redact_paths(&upstream_request.uri.path().split("/").collect::<Vec<_>>())
				.iter()
				.map(|x| {
					dbg!(x);
					x.pretty_print()
				}),
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
		session.req_header_mut().set_method(Method::POST);
		let uri = "/new/cool?path#frag".parse::<http::Uri>().unwrap();
		session.req_header_mut().set_uri(uri);
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
