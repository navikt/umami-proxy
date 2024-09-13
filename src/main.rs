use std::net::ToSocketAddrs;

use clap::Parser;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};

mod annotate;
mod config;
mod probes;
mod proxy;
// RUST_LOG=INFO cargo run --example modify_response
// curl 127.0.0.1:6191
fn main() {
	let conf = config::Config::parse();
	dbg!(&conf);
	let mut amplitrude_proxy = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: None,
	}))
	.unwrap();
	amplitrude_proxy.bootstrap();

	let reader = maxminddb::Reader::open_readfile("src/data/geolite2-city-ipv4.mmdb").unwrap();

	let mut probe_instance =
		pingora_proxy::http_proxy_service(&amplitrude_proxy.configuration, probes::Probes {});
	let mut proxy_instance = pingora_proxy::http_proxy_service(
		&amplitrude_proxy.configuration,
		/* We test against this server
		socat \
			-v -d -d \
			TCP-LISTEN:1234,crlf,reuseaddr,fork \
			SYSTEM:"
				echo HTTP/1.1 200 OK;
				echo Content-Type\: text/plain;
				echo;
			"
		*/
		proxy::Addr {
			addr: (conf.amplitude_addr, 8080)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
			reader,
		},
	);

	probe_instance.add_tcp("127.0.0.1:6969");
	proxy_instance.add_tcp("127.0.0.1:6191");
	// amplitrude_proxy.add_service(prometheus_service_http); Pingora has a built in prometheus bit. It lives in Services somewhere
	amplitrude_proxy.add_service(probe_instance);
	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.run_forever();
}
