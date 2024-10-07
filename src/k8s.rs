use crate::cache::AppInfo;
use crate::cache::CACHE;
use crate::metrics::NEW_INGRESS;
use futures::TryStreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
	api::{Api, ListParams, ResourceExt},
	runtime::{watcher, WatchStreamExt},
	Client,
};
use tracing::{info, warn};

pub async fn populate_cache() -> Result<(), Box<dyn std::error::Error>> {
	info!("populating cache");
	let client = Client::try_default().await?;
	let ingress_api: Api<Ingress> = Api::all(client.clone());
	let lp = ListParams::default();
	let ingress_list = ingress_api.list(&lp).await?;
	let mut cache = CACHE.lock().unwrap();
	for ingress in ingress_list {
		if let Some(app_info) = ingress_to_app_info(&ingress) {
			warn!("added an ingress: {:?}", app_info);
			cache.put(app_info.ingress.clone(), app_info);
		}
	}

	// this should be a gauge.
	info!(
		"Cache initially populated with {} ingress entries",
		cache.len()
	);

	Ok(())
}

pub async fn run_watcher() -> Result<(), Box<dyn std::error::Error>> {
	let client = Client::try_default().await?;
	let ingress_api: Api<Ingress> = Api::all(client.clone());
	let lp = ListParams::default();
	let wc = watcher::Config::default().labels("app,team");

	watcher(ingress_api, wc)
		.applied_objects()
		.default_backoff()
		.try_for_each(move |ingress| async move {
			let mut cache = CACHE.lock().unwrap();
			if let Some(app_info) = ingress_to_app_info(&ingress) {
				// this should be a gauge + 1
				info!("New Ingress found, {}", app_info.app);
				NEW_INGRESS.inc(); // We epxect this to eventually be not zero
				cache.put(app_info.ingress.clone(), app_info);
			}
			Ok(())
		})
		.await?;

	Ok(())
}
fn ingress_to_app_info(ingress: &Ingress) -> Option<AppInfo> {
	let app = ingress.metadata.labels.as_ref()?.get("app")?.to_string();
	let namespace = ingress.metadata.namespace.as_ref()?.to_string();
	let ingress_url = ingress.spec.as_ref()?.rules.as_ref()?[0].host.clone()?;
	let creation_timestamp = ingress.metadata.creation_timestamp.as_ref()?.0.to_string();

	Some(AppInfo {
		app,
		namespace,
		ingress: ingress_url,
		creation_timestamp,
	})
}
