use pingora::services::listening::Service;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};
use std::net::ToSocketAddrs;
use tracing::info;
mod cache;
mod config;
mod health;
mod k8s;
mod metrics;
mod proxy;
mod trace;

fn main() {
	let conf = config::Config::new();
	trace::init();
	info!("started proxy{:#?}", &conf);
	let mut amplitrude_proxy = Server::new(Some(Opt {
		upgrade: false,
		daemon: false,
		nocapture: false,
		test: false,
		conf: None,
	}))
	.unwrap();

	amplitrude_proxy.bootstrap();

	let proxy = proxy::AmplitudeProxy::new(
		conf.clone(),
		format!(
			"{}:{}",
			conf.upstream_amplitude.host.to_owned(),
			conf.upstream_amplitude.port.to_owned()
		)
		.to_socket_addrs()
		.unwrap()
		.next()
		.unwrap(),
		conf.upstream_amplitude.sni.to_owned(),
	);

	let mut probe_instance =
		pingora_proxy::http_proxy_service(&amplitrude_proxy.configuration, health::Probes {});
	let mut proxy_instance =
		pingora_proxy::http_proxy_service(&amplitrude_proxy.configuration, proxy);

	let mut prome_service_http = Service::prometheus_http_service();
	prome_service_http.add_tcp("0.0.0.0:9090");
	probe_instance.add_tcp("0.0.0.0:6969");
	proxy_instance.add_tcp("0.0.0.0:6191");
	amplitrude_proxy.add_service(probe_instance);
	amplitrude_proxy.add_service(proxy_instance);
	amplitrude_proxy.add_service(prome_service_http);
	amplitrude_proxy.run_forever();
}
