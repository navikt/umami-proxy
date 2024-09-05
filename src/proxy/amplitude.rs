use amplitude::Event;
use bytes::Bytes;
use serde_json::Value;

use crate::proxy::redact::redact_json;

fn clean_up_json(json: &mut Value, key: Option<&str>) {
	match key {
		Some(k) => redact_json(
			json.get_mut(k)
				.expect("Attempted to clean up non-existing key in JSON"),
		),
		None => redact_json(json),
	}
}

/// This function does all the manipulation/treatment of the HTTP request body received from some browser's amplitude sdk
/// 1. Parse bytes as some version of an Amplitude event; TODO: Check/handle multiple versions?
/// 1. Replace (coarsen) downstream IP w/(coarse) geo data; TODO
/// 1. Set `ProxyVersion` to name of this app (so we @ NAV can identify where the Amplitude event came from over @ Amplitude)
/// 1. Use the `crate::proxy::redact` module's logic to redact any data inside `(event|user)_properties` of the event body
pub(crate) fn process_amplitude_event(body: &Vec<u8>) -> Option<Bytes> {
	let mut json: serde_json::Value = match serde_json::de::from_slice(body) {
		Err(e) => {
			eprintln!("JSON not well-formed: {e}");
			return None;
		},
		Ok(j) => j,
	};
	dbg!(&json);

	// Clean up client-specified data
	clean_up_json(&mut json, Some("event_properties"));
	clean_up_json(&mut json, Some("user_properties"));
	let mut event = match Event::from_json(json.clone()) {
		Err(e) => {
			eprintln!("Amplitude event not well-formed: {e}");
			return None;
		},
		Ok(e) => e,
	};

	// Clean up anything else left
	redact_json(&mut json);

	// Obfuscate ID of event w/ID of proxy
	event.user_id(std::env::var("NAIS_CLIENT_ID").unwrap_or(env!("CARGO_PKG_NAME").to_string()));

	dbg!(&event);
	match serde_json::to_string(&event) {
		Ok(s) => Some(Bytes::copy_from_slice(s.as_bytes())),
		Err(e) => {
			eprintln!("Handled Amplitude event is not well-formed JSON: {e}");
			return None;
		},
	}
}
