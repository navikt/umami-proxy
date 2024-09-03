use std::net::ToSocketAddrs;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;

mod proxy;
use proxy::*;
mod config;
mod redact;

// RUST_LOG=INFO cargo run --example modify_response
// curl 127.0.0.1:6191
fn main() {
	let config = config::Config::new().expect("Configuration");
	env_logger::init();
	let mut amplitrude_proxy = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: None,
	}))
	.unwrap();
	amplitrude_proxy.bootstrap();

	let mut proxy_instance = pingora_proxy::http_proxy_service(
		&amplitrude_proxy.configuration,
		Addr {
			// hardcode socat-echno socat -v tcp-l:1234,fork exec:'/bin/cat'
			addr: ("127.0.0.1", 1234)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
		},
	);

	proxy_instance.add_tcp("127.0.0.1:6191");

	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.run_forever();
}
