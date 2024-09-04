use std::net::ToSocketAddrs;

use pingora::services::Service;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;

mod proxy;
use proxy::*;
mod config;
mod probes;
mod redact;

// RUST_LOG=INFO cargo run --example modify_response
// curl 127.0.0.1:6191
fn main() {
	let config = config::Config::new();
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

	let mut probe_instance =
		pingora_proxy::http_proxy_service(&amplitrude_proxy.configuration, probes::Probes {});
	let mut proxy_instance = pingora_proxy::http_proxy_service(
		&amplitrude_proxy.configuration,
		Addr {
			/* We test against this server
			socat \
				-v -d -d \
				TCP-LISTEN:1234,crlf,reuseaddr,fork \
				SYSTEM:"
					echo HTTP/1.1 200 OK;
					echo Content-Type\: text/plain;
					echo;
					echo \"Server: \$SOCAT_SOCKADDR:\$SOCAT_SOCKPORT\";
					echo \"Client: \$SOCAT_PEERADDR:\$SOCAT_PEERPORT\";
				"

								*/
			addr: ("127.0.0.1", 1234)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
		},
	);

	probe_instance.add_tcp("127.0.0.1:6969");
	proxy_instance.add_tcp("127.0.0.1:6191");
	// amplitrude_proxy.add_service(prometheus_service_http); Pingora has a built in prometheus bit. It lives in Services somewhere
	amplitrude_proxy.add_service(probe_instance);
	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.run_forever();
}
