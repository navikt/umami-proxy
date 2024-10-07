use crate::metrics::{INGRESS_COUNT, NEW_INGRESS};
use futures::TryStreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
	api::{Api, ListParams},
	runtime::{watcher, WatchStreamExt},
	Client,
};
use tracing::{info, warn};
pub mod cache;

pub async fn populate_cache() -> Result<(), Box<dyn std::error::Error>> {
	info!("populating cache");
	let client = Client::try_default().await?;
	let ingress_api: Api<Ingress> = Api::all(client.clone());
	let lp = ListParams::default();
	let ingress_list = ingress_api.list(&lp).await?;
	let mut cache = cache::CACHE.lock().unwrap();
	for ingress in ingress_list {
		if let Some(app_info) = ingress_to_app_info(&ingress) {
			warn!("added an ingress: {:?}", app_info);
			cache.put(app_info.ingress.clone(), app_info);
		}
	}

	let cache_length = cache.len();
	INGRESS_COUNT.set(cache_length as f64);

	info!(
		"Cache initially populated with {} ingress entries",
		cache.len()
	);

	Ok(())
}

pub async fn run_watcher() -> Result<(), Box<dyn std::error::Error>> {
	let client = Client::try_default().await?;
	let ingress_api: Api<Ingress> = Api::all(client.clone());
	let wc = watcher::Config::default().labels("app,team");
	info!("Started ingress wathcer");
	watcher(ingress_api, wc)
		.applied_objects()
		.default_backoff()
		.try_for_each(move |ingress| async move {
			let mut cache = cache::CACHE.lock().unwrap();
			if let Some(app_info) = ingress_to_app_info(&ingress) {
				info!("New Ingress found, {}", app_info.app);
				INGRESS_COUNT.inc();
				cache.put(app_info.ingress.clone(), app_info);
			}
			Ok(())
		})
		.await?;

	Ok(())
}
fn ingress_to_app_info(ingress: &Ingress) -> Option<cache::AppInfo> {
	let app = ingress.metadata.labels.as_ref()?.get("app")?.to_string();
	let namespace = ingress.metadata.namespace.as_ref()?.to_string();
	let ingress_url = ingress.spec.as_ref()?.rules.as_ref()?[0].host.clone()?;
	let creation_timestamp = ingress.metadata.creation_timestamp.as_ref()?.0.to_string();

	Some(cache::AppInfo {
		app,
		namespace,
		ingress: ingress_url,
		creation_timestamp,
	})
}
