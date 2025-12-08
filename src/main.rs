use pingora::services::listening::Service;
use pingora::{prelude::Opt, proxy as pingora_proxy, server::Server};
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

	let proxy = proxy::Umami::new(conf.clone(), isbot::Bots::default());

	let mut probe_instance =
		pingora_proxy::http_proxy_service(&umami_proxy.configuration, health::Probes {});
	let mut proxy_instance = pingora_proxy::http_proxy_service(&umami_proxy.configuration, proxy);

	// All services get allocated threads: from the config. Someone should upstream more granularity on that
	let mut prome_service_http = Service::prometheus_http_service();
	prome_service_http.add_tcp("0.0.0.0:9090");
	probe_instance.add_tcp("0.0.0.0:6969");
	proxy_instance.add_tcp("0.0.0.0:6191");
	umami_proxy.add_service(probe_instance);
	umami_proxy.add_service(proxy_instance);
	umami_proxy.add_service(prome_service_http);
	umami_proxy.run_forever();
}
