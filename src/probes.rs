use crate::redact::{print_query, redact_paths, redact_queries};
use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::{Method, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::net::ToSocketAddrs;

pub struct Probes;

#[derive(Debug)]
pub struct Ctx {
	buffer: Vec<u8>,
}

#[async_trait]
impl ProxyHttp for Probes {
	type CTX = Ctx;
	fn new_ctx(&self) -> Self::CTX {
		Ctx { buffer: vec![] }
	}

	async fn upstream_peer(
		&self,
		session: &mut Session,
		ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		let host = session.downstream_session.req_header();
		dbg!(session.downstream_session.request_summary());
		dbg!(host);

		let peer = Box::new(HttpPeer::new("localhost", false, "localhost".to_owned()));
		Ok(peer)
	}

	/// Handle the incoming request.
	///
	/// In this phase, users can parse, validate, rate limit, perform access control and/or
	/// return a response for this request.
	///
	/// If the user already sent a response to this request, an `Ok(true)` should be returned so that
	/// the proxy would exit. The proxy continues to the next phases when `Ok(false)` is returned.
	///
	/// By default this filter does nothing and returns `Ok(false)`.
	async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		dbg!(session.request_summary());
		if session
			.downstream_session
			.req_header()
			.as_owned_parts()
			.uri
			.path()
			.contains("is_alive")
		// this also matches is_aliveeeeeeeee etc
		{
			session.respond_error(200).await?; // Can we respond without saying error?
		}
		session.respond_error(404).await?;
		Ok(true)
	}
}
