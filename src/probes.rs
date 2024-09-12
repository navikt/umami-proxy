use async_trait::async_trait;
use pingora::{
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Error, ErrorType, Result,
};

pub struct Probes;

#[derive(Debug)]
pub struct Ctx {}

#[async_trait]
impl ProxyHttp for Probes {
	type CTX = Ctx;
	fn new_ctx(&self) -> Self::CTX {
		Ctx {}
	}

	async fn upstream_peer(
		&self,
		session: &mut Session,
		_ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		if let Some(peer_addr) = session.downstream_session.client_addr() {
			// Create a new upstream peer using the downstream's address
			let peer = Box::new(HttpPeer::new(peer_addr.to_string(), false, "".into()));
			return Ok(peer);
		}

		let peer = Box::new(HttpPeer::new("localhost", false, "localhost".to_owned()));
		// TODO, this should be a pingora error rather than a fake host.
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
