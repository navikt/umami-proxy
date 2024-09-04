use async_trait::async_trait;
use bytes::Bytes;
use pingora::{
	http::RequestHeader,
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Result,
};

mod amplitude;
mod redact;

pub const HOST: &str = "localhost";

pub struct Addr {
	pub addr: std::net::SocketAddr,
}

#[derive(Debug)]
pub struct Ctx {
	request_body_buffer: Vec<u8>,
}

#[async_trait]
impl ProxyHttp for Addr {
	type CTX = Ctx;
	fn new_ctx(&self) -> Self::CTX {
		Ctx {
			request_body_buffer: Vec::new(),
		}
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
			ctx.request_body_buffer.extend(&b[..]);
			// drop the body
			b.clear();
		}
		if end_of_stream {
			// This is the last chunk, we can process the data now
			*body = amplitude::process_amplitude_event(&ctx.request_body_buffer);
		}
		Ok(None)
	}

	/// Redact path and query parameters of request
	/// TODO: Also ensure fragment is redacted?
	async fn upstream_request_filter(
		&self,
		_session: &mut Session,
		upstream_request: &mut RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		upstream_request.set_uri(redact::redact_uri(&upstream_request.uri));
		Ok(())
	}

	/// Block user-agent strings that match known bots
	async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		let user_agent = session.downstream_session.get_header("USER-AGENT").cloned();
		match user_agent {
			Some(ua) => match ua.to_str() {
				Ok(ua) => {
					let bot = isbot::Bots::default().is_bot(ua);
					//  ^  This should be instanciated top-level
					session.respond_error(200).await?;
					if bot {
						eprintln!("This request's UA matches a known bot:\n\t{ua}");
					}
					return Ok(bot);
				},
				Err(_) => return Ok(false),
			},
			None => Ok(false),
		}
	}
}
