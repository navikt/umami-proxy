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

/// This function just handles the bytes deserialization and serialization of the http request body
pub(crate) fn process_amplitude_event(body: &Vec<u8>) -> Option<Bytes> {
	let mut json: serde_json::Value = match serde_json::de::from_slice(body) {
		Err(e) => {
			eprintln!("JSON not well-formed: {e}");
			return None;
		},
		Ok(j) => j,
	};
	dbg!(&json);

	let processed_body = process_event(&mut json);

	dbg!(&processed_body);
	Some(Bytes::copy_from_slice(
		serde_json::to_string(&processed_body)
			.expect("Unable to serialize JSON into string")
			.as_bytes(),
	))
}

/// This function does all the manipulation/treatment of the HTTP request body received from some browser's amplitude sdk
/// 1. Parse bytes as some version of an Amplitude event; TODO: Check/handle multiple versions?
/// 1. Replace (coarsen) downstream IP w/(coarse) geo data; TODO
/// 1. Set `ProxyVersion` to name of this app (so we @ NAV can identify where the Amplitude event came from over @ Amplitude)
/// 1. Use the `crate::proxy::redact` module's logic to redact any data inside `(event|user)_properties` of the event body
fn process_event(json: &mut Value) -> Value {
	// Clean up client-specified data
	clean_up_json(json, Some("event_properties"));
	clean_up_json(json, Some("user_properties"));
	let mut event = match Event::from_json(json.clone()) {
		Err(e) => {
			panic!("Amplitude event not well-formed: {e}");
		},
		Ok(e) => e,
	};

	// Clean up anything else left
	redact_json(json);

	// Obfuscate ID of event w/ID of proxy
	event.user_id(std::env::var("NAIS_CLIENT_ID").unwrap_or(env!("CARGO_PKG_NAME").to_string()));

	serde_json::to_value(event).expect("Processed Amplitude event is not well-formed JSON")
}

#[cfg(test)]
mod tests {
	use super::*;
	use assert_json_diff::assert_json_include;
	use serde_json::json;

	#[test]
	fn test_obfuscate_user_id() {
		let mut original_json = json!({
			"user_id": "12345",
			"device_id": "device-98765",  // <- Should this be redacted??
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"page": "signup_page"
			},
			"user_properties": {
				"age": 30,
				"gender": "female",
				"location": "USA"
			},
			"app_version": "1.0.0",
			"platform": "iOS",
			"os_name": "iOS",
			"os_version": "14.4",
			"device_brand": "Apple",
			"device_model": "iPhone 12",
			"time": 5,
			"session_id": 5,
			"insert_id": "123e4567-e89b-12d3-a456-426614174000",  // <-- This guy
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip": "123.45.67.89"
		});

		let mut expected_json = original_json.clone();
		*expected_json.get_mut("user_id").unwrap() = json!(env!("CARGO_PKG_NAME"));

		// redact_json(&mut expected_json);

		assert_json_include!(actual: process_event(&mut original_json), expected: expected_json);
	}
}
