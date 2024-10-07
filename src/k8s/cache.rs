use lru::LruCache;
use once_cell::sync::Lazy;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub static CACHE: Lazy<Arc<Mutex<LruCache<String, AppInfo>>>> = Lazy::new(|| {
	Arc::new(Mutex::new(LruCache::new(
		NonZeroUsize::new(2000).expect("cache has positive capacity"),
	)))
});

// This keeps tracks of if the k8s exfiltration thread has spawned
// AtomicBool uses atomic operations provided by the CPU to ensure that reads and writes to the boolean value are indivisible (i.e atomic!). This means that no thread can see a partially-updated value. Its pretty neat. imho
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

// This is the appinfo struct as per the ingress-collector app
#[derive(Clone, Debug)]
pub struct AppInfo {
	pub app: String,
	pub namespace: String,
	pub ingress: String,
	pub creation_timestamp: String,
}
