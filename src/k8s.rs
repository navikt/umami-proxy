use crate::metrics::INGRESS_COUNT;
use futures::TryStreamExt;
use kube::{
	api::{Api, ListParams},
	runtime::{watcher, WatchStreamExt},
	Client,
};
use tracing::{info, warn};
pub mod cache;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
	group = "nais.io",
	version = "v1alpha1",
	kind = "Application",
	namespaced
)]
pub struct ApplicationT {
	pub creation_timestamp: Option<String>,
	pub ingresses: Option<Vec<String>>,
}

pub async fn populate_cache() -> Result<(), Box<dyn std::error::Error>> {
	info!("populating cache");
	let client = Client::try_default().await?;
	let app_api: Api<Application> = Api::all(client.clone());
	let lp = ListParams::default();
	let app_list = app_api.list(&lp).await?;
	let mut cache = cache::CACHE.lock().unwrap();
	for app in app_list {
		if let Some(app_info) = application_to_app_info(&app) {
			warn!("added an application: {:?}", app_info);
			cache.put(app_info.ingress.clone(), app_info);
		}
	}
	let cache_length = cache.len();
	INGRESS_COUNT.set(cache_length as f64);
	info!(
		"Cache initially populated with {} application entries",
		cache.len()
	);

	Ok(())
}

pub async fn run_watcher() -> Result<(), Box<dyn std::error::Error>> {
	let client = Client::try_default().await?;
	let app_api: Api<Application> = Api::all(client.clone());
	let wc = watcher::Config::default().labels("app,team");
	info!("Started application watcher");
	watcher(app_api, wc)
		.applied_objects()
		.default_backoff()
		.try_for_each(move |app| async move {
			let mut cache = cache::CACHE.lock().unwrap();
			if let Some(app_info) = application_to_app_info(&app) {
				info!("New Application found, {}", app_info.app);
				INGRESS_COUNT.inc();
				cache.put(app_info.ingress.clone(), app_info);
			}
			Ok(())
		})
		.await?;

	Ok(())
}

fn application_to_app_info(application: &Application) -> Option<cache::AppInfo> {
	let app = application
		.clone()
		.metadata
		.name
		.unwrap_or("unknown app name".into());
	let namespace = &application.metadata.namespace.as_ref()?.to_string();
	let ingress_url = &application.clone().spec.ingresses?.get(0)?.clone();

	let creation_timestamp = &application
		.metadata
		.creation_timestamp
		.as_ref()?
		.0
		.to_string();

	Some(cache::AppInfo {
		app: app.into(),
		namespace: namespace.into(),
		ingress: ingress_url.into(),
		creation_timestamp: creation_timestamp.into(),
	})
}
