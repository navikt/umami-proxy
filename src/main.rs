use std::fs;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use clap::Parser;
use pingora::services::listening::Service;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};
mod annotate;
mod config;
mod probes;
mod proxy;

use lazy_static::lazy_static;
use prometheus::{HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry};

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
	let mut conf = config::Config::parse();
	let amplitude_addr = "api.eu.amplitude.com:80"
		.to_socket_addrs()
		.unwrap()
		.next()
		.unwrap();

	conf.amplitude_addr = amplitude_addr.to_string();

	register_custom_metrics();
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

	let data_dir = fs::read_dir(conf.db_path).expect("data exists");
	let file = data_dir.last().unwrap().unwrap();
	dbg!(&file);
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
			addr: (conf.amplitude_addr, 8080)
				.to_socket_addrs()
				.unwrap()
				.next()
				.unwrap(),
			reader,
		},
	);

	let mut prome_service_http = Service::prometheus_http_service();
	prome_service_http.add_tcp("127.0.0.1:9090");
	probe_instance.add_tcp("127.0.0.1:6969");
	proxy_instance.add_tcp("127.0.0.1:6191");
	// amplitrude_proxy.add_service(prometheus_service_http); Pingora has a built in prometheus bit. It lives in Services somewhere
	amplitrude_proxy.add_service(probe_instance);
	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.add_service(prome_service_http);

	amplitrude_proxy.run_forever();
}
