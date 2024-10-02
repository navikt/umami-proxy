use crate::cache::AppInfo;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::watcher::{self, Event};
use kube::{
	api::{Api, ListParams},
	Client,
};
use lru::LruCache;
use std::sync::{Arc, Mutex};
use tracing::info;

pub struct K8sWatcher {
	pub cache: Arc<Mutex<LruCache<String, AppInfo>>>,
}

impl K8sWatcher {
	pub fn new(cache: Arc<Mutex<LruCache<String, AppInfo>>>) -> Self {
		K8sWatcher { cache }
	}

	pub async fn populate_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
		let client = Client::try_default().await?;
		let ingress_api: Api<Ingress> = Api::all(client.clone());
		let lp = ListParams::default();
		let ingress_list = ingress_api.list(&lp).await?;
		let mut cache = self.cache.lock().unwrap();
		for ingress in ingress_list {
			if let Some(app_info) = self.ingress_to_app_info(&ingress) {
				cache.put(app_info.ingress.clone(), app_info);
			}
		}

		info!(
			"Cache initially populated with {} ingress entries",
			cache.len()
		);

		Ok(())
	}
	pub async fn run_watcher(&self) -> Result<(), Box<dyn std::error::Error>> {
		let client = Client::try_default().await?;
		let ingress_api: Api<Ingress> = Api::all(client.clone());
		let lp = ListParams::default();

		// Idk what are StreamExts what are Wathcers wtf is an event type???
		Ok(())
	}
	fn ingress_to_app_info(&self, ingress: &Ingress) -> Option<AppInfo> {
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
}
