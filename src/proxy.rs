use std::net::ToSocketAddrs;

use crate::config::Config;
use crate::{
	annotate, ERRORS_WHILE_PROXY, HANDLED_REQUESTS, INCOMING_REQUESTS, SSL_ERROR,
	UPSTREAM_CONNECTION_FAILURES,
};
use async_trait::async_trait;
use bytes::Bytes;
use pingora::{http, Error};
use pingora::{
	http::RequestHeader,
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Result,
};
use serde_json::Value;
use tracing::{error, info};
mod redact;

pub struct AmplitudeProxy {
	pub conf: Config,
	pub addr: std::net::SocketAddr,
	pub sni: Option<String>,
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
		INCOMING_REQUESTS.inc();

		// We short circuit here because I dont want no traffic to go to upstream without
		// more unit-tests and nix tests on the redact stuff
		let user_agent = session.downstream_session.get_header("USER-AGENT").cloned();
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
		session: &mut Session,
		_ctx: &mut Self::CTX,
	) -> Result<Box<HttpPeer>> {
		let owned_parts = session.downstream_session.req_header().as_owned_parts();
		let path = owned_parts.uri.path();
		info!(path = ?path);

		let mut peer = Box::new(HttpPeer::new(
			self.addr,
			self.sni.is_some(),
			self.sni.clone().unwrap_or("".into()),
		));
		if path.starts_with("/umami") {
			peer = Box::new(HttpPeer::new(
				format!(
					"{}:{}",
					self.conf.upstream_umami.host, self.conf.upstream_umami.port
				)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
				self.conf.upstream_umami.sni.is_some(),
				self.conf.upstream_umami.sni.clone().unwrap_or("".into()),
			));
		}
		info!("peer:{}", peer);
		Ok(peer)
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
		let city = session
			.downstream_session
			.get_header("x-client-city")
			.and_then(|x| Some(x.to_str().map_or(String::new(), |s| s.to_owned())))
			.unwrap_or(String::new());

		let country = session
			.downstream_session
			.get_header("x-client-region")
			.and_then(|x| {
				Some(
					x.to_str()
						.map_or(String::from("UNKNOWN-COUNTRY-VALUE"), |s| s.to_owned()),
				)
			})
			.unwrap_or(String::from("ONKNOWN-COONTRO-VOLOO"));

		// buffer the data
		if let Some(b) = body {
			ctx.request_body_buffer.extend(&b[..]);
			// drop the body - we've consumed it as b
			b.clear();
		}
		if end_of_stream {
			// This is the last chunk, we can process the data now
			if !ctx.request_body_buffer.is_empty() {
				let json_result: Result<Value, serde_json::Error> =
					serde_json::from_slice(&ctx.request_body_buffer);

				let mut v = match json_result {
					Ok(parsed_json) => parsed_json,
					Err(e) => {
						return Err(Error::explain(
							pingora::ErrorType::Custom("invalid request-json".into()),
							"Failed to parse request body",
						));
					},
				};

				redact::traverse_and_redact(&mut v);
				annotate::annotate_with_proxy_version(&mut v, "1.0.0");

				let json_body_result = serde_json::to_string(&v);

				match json_body_result {
					Ok(json_body) => {
						*body = Some(Bytes::from(json_body));
					},
					Err(e) => {
						return Err(Error::explain(
							pingora::ErrorType::Custom("invalid json after redacting".into()),
							"Failed to co-parse redacted request body",
						));
					},
				}
			}
		}

		Ok(())
	}

	/// Redact path and query parameters of request
	/// TODO: Also ensure that path fragments are redacted?
	async fn upstream_request_filter(
		&self,
		session: &mut Session,
		upstream_request: &mut RequestHeader,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		// It's hard to know how big the body is before we start touching it
		// We work around that by removing content length and setting the
		// transfer encoding as chunked. The source code in pingora core looks like it would
		// do it automatically, but I don't see it happening, hence the explicit bits here
		info!("upstream_requst_filter");
		let city = session
			.downstream_session
			.get_header("x-client-city")
			.and_then(|x| Some(x.to_str().map_or(String::new(), |s| s.to_owned())))
			.unwrap_or(String::new());

		let region = session
			.downstream_session
			.get_header("x-client-region")
			.and_then(|x| {
				Some(
					x.to_str()
						.map_or(String::from("UNKNOWN-COUNTRY-VALUE"), |s| s.to_owned()),
				)
			})
			.unwrap_or(String::from("ONKNOWN-COONTRO-VOLOO"));

		upstream_request.remove_header("Content-Length");
		upstream_request
			.insert_header("Transfer-Encoding", "Chunked")
			.unwrap();

		upstream_request
			.insert_header("X-Vercel-IP-Country", region)
			.unwrap();

		upstream_request
			.insert_header("X-Vercel-City", city)
			.unwrap();

		upstream_request
			.insert_header("Host", "api.eu.amplitude.com")
			.expect("Needs correct Host header");

		let path = upstream_request.uri.path();
		info!("{}", &path);
		if path.starts_with("/umami") {
			upstream_request
				.insert_header("Host", "umami.nav.no")
				.expect("Needs correct Host header");

			// unwrap, unwrap, unwrap. :(
			// There's also an ip4 vs ip6 consideration to be made here
			let client_addr = session
				.downstream_session
				.client_addr()
				.unwrap()
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap()
				.ip()
				.to_string();

			dbg!(&client_addr);
			// The X-Forwarded-For header is added here because otherwise umami will put
			// all our users in the datacenter, which is in Nowhere, Finland.
			// Amplitude doesn't need this as they do geolocation client side(???)
			upstream_request
				.insert_header("X-Forwarded-For", client_addr)
				.unwrap();
		}

		// Redact the uris, path segements and query params
		upstream_request.set_uri(redact::redact_uri(&upstream_request.uri));
		info!("upstream request filter, {}", &upstream_request.uri);
		Ok(())
	}

	async fn logging(&self, _session: &mut Session, e: Option<&Error>, _ctx: &mut Self::CTX)
	where
		Self::CTX: Send + Sync,
	{
		info!("log: {}", _session.request_summary());
		let Some(err) = e else {
			// happy path
			HANDLED_REQUESTS.inc();
			return ();
		};

		// Some error happened
		ERRORS_WHILE_PROXY.inc();
		error!("{:?}", err);
		use pingora::ErrorType as ErrType;
		match err.etype {
			ErrType::TLSHandshakeFailure
			| ErrType::TLSHandshakeTimedout
			| ErrType::InvalidCert
			| ErrType::HandshakeError => SSL_ERROR.inc(),

			ErrType::ConnectTimedout
			| ErrType::ConnectRefused
			| ErrType::ConnectNoRoute
			| ErrType::ConnectError
			| ErrType::BindError
			| ErrType::AcceptError
			| ErrType::SocketError => ERRORS_WHILE_PROXY.inc(), // This guy is used twice.

			ErrType::ConnectProxyFailure => UPSTREAM_CONNECTION_FAILURES.inc(),

			// All the rest are ignored for now, bring in when needed
			_ => {},
		};
		()
	}
}
