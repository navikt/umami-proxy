use lru::LruCache;
use once_cell::sync::Lazy;
use ptrie::Trie;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub static CACHE: Lazy<Arc<Mutex<LruCache<String, AppInfo>>>> = Lazy::new(|| {
	Arc::new(Mutex::new(LruCache::new(
		NonZeroUsize::new(2000).expect("cache has positive capacity"),
	)))
});

// Would it make sense to prefix-lookup on appInfo records instead? Can I do that? This only exists for longest-prefix matching
pub static PREFIX_TRIE: Lazy<Arc<Mutex<Trie<u8, String>>>> =
	Lazy::new(|| Arc::new(Mutex::new(Trie::new())));

// Thiskeeps tracks of if the k8s exfiltration thread has spawned
// AtomicBool uses atomic operations provided by the CPU to ensure that reads and writes to the boolean value are indivisible (i.e atomic!). This means that no thread can see a partially-updated value. Its pretty neat. imho
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

// This is the appinfo struct as per the ingress-collector app
#[derive(Clone, Debug, PartialEq)]
pub struct AppInfo {
	pub app: String,
	pub namespace: String,
	pub ingress: String,
	pub creation_timestamp: String,
}

pub fn insert_into_cache(key: String, value: AppInfo) {
	let mut cache = CACHE.lock().expect("Failed to lock cache");
	cache.put(key.clone(), value);

	let mut trie = PREFIX_TRIE.lock().expect("Failed to lock trie");
	trie.insert(key.clone().bytes(), key);
}

pub fn get_app_info_with_longest_prefix(key: String) -> Option<AppInfo> {
	let trie = PREFIX_TRIE.lock().expect("Failed to lock trie");

	if let Some(longest_prefix) = trie.find_longest_prefix(key.bytes()) {
		let mut cache = CACHE.lock().expect("Failed to lock cache");
		dbg!("is prefix!{}", longest_prefix);
		return cache.get(&longest_prefix.clone()).cloned();
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_insert_and_retrieve_from_cache() {
		let key = "test-key".to_string();
		let app_info = AppInfo {
			app: "test-app".to_string(),
			namespace: "test-namespace".to_string(),
			ingress: "test-ingress".to_string(),
			creation_timestamp: "2023-01-01T00:00:00Z".to_string(),
		};

		insert_into_cache(key.clone(), app_info.clone());
		insert_into_cache(key.clone(), app_info.clone());

		let retrieved_app_info = get_app_info_with_longest_prefix(key.clone());
		assert!(
			retrieved_app_info.is_some(),
			"AppInfo should be present in cache"
		);
		assert_eq!(
			retrieved_app_info.unwrap(),
			app_info,
			"Retrieved AppInfo should match inserted value"
		);

		let prefix_key = "test-key-key-key".to_string();
		let prefix_app_info = get_app_info_with_longest_prefix(prefix_key).unwrap();
		assert_eq!(
			prefix_app_info, app_info,
			"Prefix-based retrieval should match inserted AppInfo"
		);
	}
}
