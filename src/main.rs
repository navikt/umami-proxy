use pingora::services::listening::Service;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};
use std::net::ToSocketAddrs;
use tracing::info;
mod config;
mod errors;
mod health;
mod k8s;
mod metrics;
mod proxy;
mod trace;

fn main() {
	let conf = config::Config::new();
	trace::init();
	info!("started proxy{:#?}", &conf);
	let mut umami_proxy = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: Some("./conf/conf.yaml".into()),
	}))
	.expect("Default args should work");

	umami_proxy.bootstrap();

	let proxy = proxy::Umami::new(
		conf.clone(),
		format!("{}:{}", conf.host, conf.port,)
			.to_socket_addrs()
			.expect("Amplitude specified `host` & `port` should give valid `std::net::SocketAddr`")
			.next()
			.expect("SocketAddr should resolve to at least 1 IP address"),
		conf.sni,
		isbot::Bots::default(),
	);

	let mut probe_instance =
		pingora_proxy::http_proxy_service(&umami_proxy.configuration, health::Probes {});
	let mut proxy_instance = pingora_proxy::http_proxy_service(&umami_proxy.configuration, proxy);

	// All services get allocated threads: from the config. Someone should upstream more granularity on that
	let mut prome_service_http = Service::prometheus_http_service();
	prome_service_http.add_tcp(format!("0.0.0.0:{}", conf.metrics_listen_port));
	probe_instance.add_tcp(format!("0.0.0.0:{}", conf.probe_listen_port));
	proxy_instance.add_tcp(format!("0.0.0.0:{}", conf.proxy_listen_port));
	umami_proxy.add_service(probe_instance);
	umami_proxy.add_service(proxy_instance);
	umami_proxy.add_service(prome_service_http);
	umami_proxy.run_forever();
}
