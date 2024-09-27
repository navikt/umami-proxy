use crate::config;
use crate::{annotate, INCOMING_REQUESTS};
use async_trait::async_trait;
use bytes::Bytes;
use maxminddb::Reader;
use pingora::Error;
use pingora::{
	http::RequestHeader,
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Result,
};
use tracing::{error, info};
mod redact;
use prometheus::{self, Encoder, TextEncoder};

pub struct AmplitudeProxy {
	pub addr: std::net::SocketAddr,
	pub reader: Reader<Vec<u8>>, // for maxmindb
	pub sni: String,
}

#[derive(Debug)]
pub struct Ctx {
	request_body_buffer: Vec<u8>,
}

#[async_trait]
impl ProxyHttp for AmplitudeProxy {
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
		info!("{}", &session.request_summary());

		// We short circuit here because I dont want no traffic to go to upstream without
		// more unit-tests and nix tests on the redact stuff
		let user_agent = session.downstream_session.get_header("USER-AGENT").cloned();
		INCOMING_REQUESTS.inc();
		match user_agent {
			Some(ua) => match ua.to_str() {
				Ok(ua) => {
					let bot = isbot::Bots::default().is_bot(ua);
					//  ^  This should be instanciated top-level, in the ctx

					if bot {
						session.respond_error(403).await?;
						// ^ This respond_error bit is silly, surely we can just respond?
						info!("This request's UA matches a known bot:\n\t{ua}");
						return Ok(bot);
					}
					Ok(false)
				},
				Err(e) => {
					error!("Err :\n\t{e}");
					return Ok(false);
				},
			},
			None => Ok(false),
		}
	}
	// This guy should be the upstream host, all requests through the proxy gets sent th upstream_peer
	async fn upstream_peer(
		&self,
		_session: &mut Session,
		_ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		INCOMING_REQUESTS.inc();

		let peer = Box::new(HttpPeer::new(self.addr, true, self.sni.clone()));
		info!("peer:{}", peer);
		Ok(peer)
	}

	fn fail_to_connect(
		&self,
		_session: &mut Session,
		_peer: &HttpPeer,
		_ctx: &mut Self::CTX,
		e: Box<Error>,
	) -> Box<Error> {
		info!("FAIL TO CONNECT: {}", e);
		e
	}
	async fn request_body_filter(
		&self,
		session: &mut Session,
		body: &mut Option<Bytes>,
		end_of_stream: bool,
		ctx: &mut Self::CTX,
	) -> Result<()>
	where
		Self::CTX: Send + Sync,
	{
		info!("Request body filter, {}", session.request_summary());
		// buffer the data
		if let Some(b) = body {
			ctx.request_body_buffer.extend(&b[..]);
			// drop the body - we've consumed it as b
			b.clear();
		}
		if end_of_stream {
			// This is the last chunk, we can process the data now
			// If there is a body...
			if !ctx.request_body_buffer.is_empty() {
				let mut v: serde_json::Value =
					serde_json::from_slice(&ctx.request_body_buffer).expect("invalid json");
				redact::traverse_and_redact(&mut v);
				annotate::annotate_with_proxy_version(&mut v, "1.0.0");

				let json_body = serde_json::to_string(&v).expect("invalid redacted json");

				*body = Some(Bytes::from(json_body));
			}
		}

		// Register & measure some metrics.
		let mut buffer = Vec::new();
		let encoder = TextEncoder::new();

		let metric_families = prometheus::gather();
		// Encode them to send.
		encoder.encode(&metric_families, &mut buffer).unwrap();
		Ok(())
	}

	/// Redact path and query parameters of request
	/// TODO: Also ensure that path fragments are redacted?
	async fn upstream_request_filter(
		&self,
		_session: &mut Session,
		upstream_request: &mut RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		// It's hard to know how big the body is before we start touching it
		// We work around that by removing content length and setting the
		// transfer encoding as chunked. The source code in pingora core looks like it would
		// do it automatically, but I don't see it happening, hence the explicit bits here
		info!("upstream_requst_filter");
		upstream_request.remove_header("Content-Length");
		upstream_request
			.insert_header("Transfer-Encoding", "Chunked")
			.unwrap();

		// Redact the uris, path segements and query params
		// 	upstream_request.set_uri(redact::redact_uri(&upstream_request.uri));
		info!("upstream request filter, {}", &upstream_request.uri);
		Ok(())
	}
}
