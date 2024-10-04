use crate::cache::{self, INITIALIZED};
use crate::config::Config;
use crate::{
	annotate, k8s, CONNECTION_ERRORS, ERRORS_WHILE_PROXY, HANDLED_REQUESTS, INCOMING_REQUESTS,
	SSL_ERROR, UPSTREAM_CONNECTION_FAILURES,
};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Error;
use pingora::ErrorType as ErrType;
use pingora::{
	http::RequestHeader,
	prelude::HttpPeer,
	proxy::{ProxyHttp, Session},
	Result,
};
use serde_json::Value;
use std::net::ToSocketAddrs;
use tracing::{error, info, warn};
mod redact;

use std::sync::atomic::Ordering;

pub struct AmplitudeProxy {
	pub conf: Config,
	pub addr: std::net::SocketAddr,
	pub sni: Option<String>,
}

impl AmplitudeProxy {
	pub fn new(conf: Config, addr: std::net::SocketAddr, sni: Option<String>) -> AmplitudeProxy {
		AmplitudeProxy { conf, addr, sni }
	}
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
		if !INITIALIZED.load(Ordering::Relaxed) {
			// We only ever want to spawn this thread once. It reads all ingresses once and then sits
			// around watching changes to ingresses
			if let Ok(_) =
				// This is double checked locking, if you squint.
				// https://en.wikipedia.org/wiki/Double-checked_locking
				INITIALIZED.compare_exchange(
					false,
					true,
					Ordering::SeqCst, // sequenctially consistent
					Ordering::Relaxed,
				) {
				// This should have a gauge to show that we only ever have one (or zero ) of these
				tokio::spawn(async {
					let e1 = k8s::populate_cache();
					warn!("populating cache: {:?}", e1.await);
					let e2 = k8s::run_watcher().await;
				});
			}
		}

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

		let peer = if path.starts_with("/umami") {
			Box::new(HttpPeer::new(
				format!(
					"{}:{}",
					self.conf.upstream_umami.host, self.conf.upstream_umami.port
				)
				.to_socket_addrs()
				.expect("Umami specified `host` & `port` should give valid `std::net::SocketAddr`")
				.next()
				.expect(" SocketAddr should resolve to at minimum 1x IP addr"),
				self.conf.upstream_umami.sni.is_some(),
				self.conf
					.upstream_umami
					.sni
					.clone()
					.unwrap_or_else(|| "".into()),
			))
		} else {
			Box::new(HttpPeer::new(
				self.addr,
				self.sni.is_some(),
				self.sni.clone().unwrap_or_else(|| "".into()),
			))
		};
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
			.map_or_else(
				|| {
					String::from("Missing city header, this should not happen, the GCP loadbalancer adds these",)
				},
				|x| {
					x.to_str()
						.map_or(String::new(), std::borrow::ToOwned::to_owned)
				},
			);

		let country = session
			.downstream_session
			.get_header("x-client-region")
			.map_or_else(
				|| {
					String::from("Missing country header, this should not happen the GCP loadbalancer adds these")
				},
				|x| {
					x.to_str()
						.map_or(String::from(""), std::borrow::ToOwned::to_owned)
				},
			);

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

				let Ok(mut v) = json_result else {
					return {
						let s = String::from_utf8_lossy(&ctx.request_body_buffer);
						dbg!("BUFFER {:?}", s);
						Err(Error::explain(
							pingora::ErrorType::Custom("invalid request-json"),
							"Failed to parse request body",
						))
					};
				};

				redact::traverse_and_redact(&mut v);
				annotate::annotate_with_proxy_version(&mut v, "amplitrude-1.0.0");

				// This uses exactly "event_properties, which maybe only amplitude has"
				annotate::annotate_with_location(&mut v, &city, &country);

				let json_body_result = serde_json::to_string(&v);

				match json_body_result {
					Ok(json_body) => {
						*body = Some(Bytes::from(json_body));
					},
					Err(_) => {
						return Err(Error::explain(
							pingora::ErrorType::Custom("invalid json after redacting"),
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
		info!("upstream_requst_filter");
		let city = session
			.downstream_session
			.get_header("x-client-city")
			.map(|x| x.to_str())
			.map_or_else(String::new, |s| s.unwrap_or("").to_string());

		let region = session
			.downstream_session
			.get_header("x-client-region")
			.map(|x| x.to_str())
			.map_or_else(
				|| String::from("UNKNOWN-COUNTRY-VALUE"),
				|s| s.unwrap_or("ONKNOWN-COONTRO-VOLOO").to_string(),
			);

		// It's hard to know how big the body is before we start touching it
		// We work around that by removing content length and setting the
		// transfer encoding as chunked. The source code in pingora core looks like it would
		// do it automatically, but I don't see it happening, hence the explicit bits here
		upstream_request.remove_header("Content-Length");
		upstream_request
			.insert_header("Transfer-Encoding", "Chunked")
			.unwrap();

		// We are using vercel headers here because Umami supports them
		// and they are not configurable. We already have this info in the request
		// as x-client-city, x-client-country but umami does not support those names.
		// (umami also supports Cloudflare headers, which we aren't (but could be) using )
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
			    .insert_header("Host", "umami.nav.no") // This is egress but could be by service discovery too, but i dont want to think about tls right now.
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

			// The X-Forwarded-For header is added here because otherwise umami will put
			// all our users in the datacenter, which is in Nowhere, Finland.
			// Amplitude doesn't need this as they do geolocation client side(???)
			upstream_request
				.insert_header("X-Forwarded-For", client_addr)
				.unwrap();
		}

		// Redact the uris, path segements and query params
		upstream_request.set_uri(redact::redact_uri(&upstream_request.uri));
		Ok(())
	}

	async fn logging(&self, _session: &mut Session, e: Option<&Error>, _ctx: &mut Self::CTX)
	where
		Self::CTX: Send + Sync,
	{
		let Some(err) = e else {
			// happy path
			HANDLED_REQUESTS.inc();
			return;
		};
		info!("cache size: {}", cache::CACHE.lock().unwrap().len());

		// Some error happened
		ERRORS_WHILE_PROXY.inc();
		error!("{:?}", err);
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
			| ErrType::SocketError => CONNECTION_ERRORS.inc(),

			ErrType::ConnectProxyFailure => UPSTREAM_CONNECTION_FAILURES.inc(),

			// All the rest are ignored for now, bring in when needed
			_ => {},
		}
	}
}
