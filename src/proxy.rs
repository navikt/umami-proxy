use std::fmt::format;

use async_trait::async_trait;
use bytes::Bytes;
use maxminddb::Reader;
use pingora::{
	http::RequestHeader,
	http::ResponseHeader,
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Result,
};

mod amplitude;
mod redact;

pub struct Addr {
	pub addr: std::net::SocketAddr,
	pub reader: Reader<Vec<u8>>, // for maxmindb
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

	/// Request_filter runs before anything else. We can for example set the peer here, through ctx
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
					//  ^  This should be instanciated top-level, in the ctx

					if bot {
						session.respond_error(222).await?;
						// ^ This respond_error bit is silly, surely we can just respond?
						eprintln!("This request's UA matches a known bot:\n\t{ua}");
						return Ok(bot);
					}
					Ok(false)
				},
				Err(e) => {
					eprintln!("Err :\n\t{e}");
					return Ok(false);
				},
			},
			None => {
				eprintln!("None");
				Ok(false)
			},
		}
	}
	// This guy should be the amplitude host, all requests through the proxy gets sent th upstream_peer
	async fn upstream_peer(
		&self,
		_session: &mut Session,
		_ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		let peer = Box::new(HttpPeer::new(self.addr, false, "".into()));
		Ok(peer)
	}

	async fn request_body_filter(
		&self,
		_session: &mut Session,
		body: &mut Option<Bytes>,
		end_of_stream: bool,
		ctx: &mut Self::CTX,
	) -> Result<()>
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
			if ctx.request_body_buffer.len() > 0 {
				let mut v: serde_json::Value =
					serde_json::from_slice(&ctx.request_body_buffer).expect("invalid json");
				redact::traverse_and_redact(&mut v);
				let json_body = serde_json::to_string(&v).expect("invalid redacted json");
				*body = Some(Bytes::from(json_body));
				dbg!(_session.request_summary());
				dbg!(&body);
			}
		}
		Ok(())
	}

	/// Redact path and query parameters of request
	/// TODO: Also ensure fragment is redacted?
	async fn upstream_request_filter(
		&self,
		_session: &mut Session,
		upstream_request: &mut RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		// It's hard to know how big the body is before we start touching it
		// We work around that by removing content length and setting the
		// transfer encoding as chunked.
		upstream_request.remove_header("Content-Length");
		upstream_request
			.insert_header("Transfer-Encoding", "Chunked")
			.unwrap();

		// Redact the uris
		upstream_request.set_uri(redact::redact_uri(&upstream_request.uri));
		Ok(())
	}
}
