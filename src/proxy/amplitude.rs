use amplitude::Event;
use bytes::Bytes;
use serde_json::Value;

use crate::proxy::redact::redact_json;

fn clean_up_json(json: &mut Value, key: Option<&str>) {
	match key {
		Some(k) => {
			if let Some(j) = json.get_mut(k) {
				redact_json(j)
			}
		},
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

fn remove_key(json: &mut Value, key: &str) {
	if let Some(j) = json.get_mut(key) {
		j.take();
	}
}

/// This function does all the manipulation/treatment of the HTTP request body received from some browser's amplitude sdk
/// 1. Parse JSON as some version of an Amplitude event; TODO: Check/handle multiple versions?
///    - NB: `amplitude::Event`'s serde implementation lossly ignores any fields
/// 		not existing over @ https://amplitude.com/docs/apis/analytics/http-v2#schemaevent
/// 1. Replace (coarsen) downstream IP w/(coarse) geo data; TODO
/// 1. Set `ProxyVersion` to name of this app (so we @ NAV can identify where the Amplitude event came from over @ Amplitude)
/// 1. Use the `crate::proxy::redact` module's logic to redact any data inside `(event|user)_properties` of the event body
fn process_event(json: &mut Value) -> Value {
	// Upstream requires this one to be present, so don't redact it
	let event_type = match json.get_mut("event_type") {
		Some(s) => s
			.as_str()
			.expect("Amplitude event's `event_type` JSON key not serializeable as string")
			.to_owned(),
		None => {
			panic!("Amplitude event missing upstream required field: `event_type`")
		},
	};

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

	// Remove consumer device identificators
	remove_key(json, "idfa");
	remove_key(json, "idfv");
	remove_key(json, "adid");
	remove_key(json, "android_id");

	// REDACT ID of event w/ID of proxy
	event.user_id(std::env::var("NAIS_CLIENT_ID").unwrap_or(env!("CARGO_PKG_NAME").to_string()));

	// Add back in upstream required (non-redacted) fields/keys
	event.event_type(event_type);
	serde_json::to_value(event).expect("Processed Amplitude event is not well-formed JSON")
}

#[cfg(test)]
mod tests {
	use super::*;
	use assert_json_diff::assert_json_include;
	use serde_json::json;

	#[test]
	fn test_redact_user_id() {
		let mut original_json = json!({
			"user_id": "12345",
			"event_type": "button_click",
		});

		let mut expected_json = original_json.clone();
		*expected_json.get_mut("user_id").unwrap() = json!(env!("CARGO_PKG_NAME"));

		assert_json_include!(actual: process_event(&mut original_json), expected: expected_json);
	}
	#[test]
	fn test_redact_phone_ids() {
		// Set-up
		let mut expected_json = json!({
			"user_id": "12345",
			"event_type": "button_click",
		});
		let mut original_json = expected_json.clone();

		// Test difference
		*expected_json.get_mut("user_id").unwrap() = json!(env!("CARGO_PKG_NAME"));
		{
			let json = original_json.as_object_mut().unwrap();
			assert!(None == json.insert("idfa".to_string(), json!("foo")));
			assert!(None == json.insert("idfv".to_string(), json!("bar")));
			assert!(None == json.insert("adid".to_string(), json!("baz")));
			assert!(None == json.insert("android_id".to_string(), json!("baw")));
		}

		// Verify
		assert_json_include!(actual: process_event(&mut original_json), expected: expected_json);
	}
}
