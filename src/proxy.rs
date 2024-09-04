use crate::redact::{print_query, redact_paths, redact_queries};
use async_trait::async_trait;
use http::Uri;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};

pub const HOST: &str = "localhost";

#[derive(Serialize, Deserialize)]
pub struct Resp {
	ip: String,
}

pub struct Addr {
	pub addr: std::net::SocketAddr,
}

#[derive(Debug)]
pub struct Ctx {}

#[async_trait]
impl ProxyHttp for Addr {
	type CTX = Ctx;
	fn new_ctx(&self) -> Self::CTX {
		Ctx {}
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

	async fn upstream_request_filter(
		&self,
		session: &mut Session,
		upstream_request: &mut pingora_http::RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		let redacted_paths = itertools::join(
			redact_paths(&upstream_request.uri.path().split('/').collect::<Vec<_>>())
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
					.split('&')
					.flat_map(|q| q.split_once('='))
					.collect::<Vec<_>>(),
			)
			.iter()
			.map(print_query),
			"&",
		);
		dbg!(session.request_summary());
		upstream_request.set_uri(
			(format!("{redacted_paths}?{redacted_queries}"))
				.parse::<Uri>()
				.unwrap(),
		);
		Ok(())
	}
	async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		let user_agent = session.downstream_session.get_header("USER-AGENT");
		dbg!(user_agent);
		match user_agent {
			Some(ua) => match ua.to_str() {
				Ok(ua) => {
					let bot = isbot::Bots::default().is_bot(ua);
					//  ^  This should be instanciated top-level
					session.respond_error(200).await?;
					return Ok(bot);
				},
				Err(_) => return Ok(false),
			},
			None => Ok(false),
		}
	}
}
