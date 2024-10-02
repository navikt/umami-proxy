use crate::AppInfo;
use futures::{StreamExt, TryStreamExt};
use kube::{
	api::{Api, ListParams},
	Client,
};
use kube_runtime::utils::try_flatten_applied;
use kube_runtime::watcher::{self, Event};
use lru::LruCache;
use serde_json::Value;
use std::sync::{Arc, Mutex};

pub struct K8sWatcher {
	pub cache: Arc<Mutex<LruCache<String, AppInfo>>>,
}

impl K8sWatcher {
	pub fn new(cache: Arc<Mutex<LruCache<String, AppInfo>>>) -> Self {
		K8sWatcher { cache }
	}

	pub async fn populate_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
		let client = Client::try_default().await?;
		let ingress_api: Api<Value> = Api::all(client.clone());
		let lp = ListParams::default();
		let ingress_list = ingress_api.list(&lp).await?;
		{
			let mut cache = self.cache.lock().unwrap();
			for ingress in ingress_list {
				if let Some(app_info) = self.ingress_to_app_info(&ingress) {
					cache.put(app_info.ingress.clone(), app_info);
				}
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

		let ingress_api: Api<Value> = Api::all(client.clone());

		let lp = ListParams::default();
		let mut ingress_watcher = try_flatten_applied(watcher(ingress_api, lp)).boxed();

		info!("Listening for Ingress updates...");

		// Process events from the watcher stream
		while let Some(event) = ingress_watcher.try_next().await? {
			match event {
				Event::Applied(ingress) => {
					let app_info = self.ingress_to_app_info(&ingress);
					if let Some(app_info) = app_info {
						let mut cache = self.cache.lock().unwrap();
						cache.put(app_info.ingress.clone(), app_info);
						update!(
							"Ingress applied/updated and added to cache: {}",
							app_info.ingress
						);
					}
				},
				Event::Deleted(ingress) => {
					if let Some(ingress_url) = ingress["spec"]["rules"][0]["host"].as_str() {
						{
							let mut cache = self.cache.lock().unwrap();
							cache.pop(ingress_url);
							info!("Ingress deleted and removed from cache: {}", ingress_url);
						}
					}
				},
				Event::Restarted(ingresses) => {
					let mut cache = self.cache.lock().unwrap();
					for ingress in ingresses {
						let app_info = self.ingress_to_app_info(&ingress);
						if let Some(app_info) = app_info {
							cache.put(app_info.ingress.clone(), app_info);
						}
					}
					info!("Cache reloaded with Ingress data after restart");
				},
			}
		}

		Ok(())
	}

	fn ingress_to_app_info(&self, ingress: &Value) -> Option<AppInfo> {
		// Extract fields from the Ingress resource
		let app = ingress["metadata"]["labels"]["app"].as_str()?.to_string();
		let namespace = ingress["metadata"]["namespace"].as_str()?.to_string();
		let ingress_url = ingress["spec"]["rules"][0]["host"].as_str()?.to_string();
		let creation_timestamp = ingress["metadata"]["creationTimestamp"]
			.as_str()?
			.to_string();

		Some(AppInfo {
			app,
			namespace,
			version,
			context,
			ingress: ingress_url,
			creation_timestamp,
		})
	}
}
