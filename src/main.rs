use std::fs;
use std::net::ToSocketAddrs;

use clap::Parser;
use pingora::services::listening::Service;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};
use tracing::info;
mod annotate;
mod config;
mod probes;
mod proxy;
mod trace;

use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};

lazy_static! {
	pub static ref REGISTRY: Registry = Registry::new();
	pub static ref INCOMING_REQUESTS: IntCounter =
		IntCounter::new("incoming_requests", "Incoming Requests").expect("metric can be created");
}

fn register_custom_metrics() {
	REGISTRY
		.register(Box::new(INCOMING_REQUESTS.clone()))
		.expect("collector can be registered");
}

fn main() {
	let conf = config::Config::parse();

	trace::init();
	info!("started proxy\n upstream: {}", conf.amplitude_addr);
	register_custom_metrics();
	let mut amplitrude_proxy = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: None,
	}))
	.unwrap();
	amplitrude_proxy.bootstrap();

	let data_dir = fs::read_dir(conf.db_path).expect("data exists");
	let file = data_dir.last().unwrap().unwrap();
	let reader = maxminddb::Reader::open_readfile(file.path()).unwrap();

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
			addr: (conf.amplitude_addr)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
			reader,
		},
	);

	let mut prome_service_http = Service::prometheus_http_service();
	prome_service_http.add_tcp("0.0.0.0:9090");
	probe_instance.add_tcp("0.0.0.0:6969");
	proxy_instance.add_tcp("0.0.0.0:6191");
	amplitrude_proxy.add_service(probe_instance);
	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.add_service(prome_service_http);

	amplitrude_proxy.run_forever();
}
