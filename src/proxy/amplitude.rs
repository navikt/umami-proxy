use amplitude::Event;
use bytes::Bytes;
use serde_json::Value;

use crate::proxy::redact::redact_json;

use super::redact;

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
	redact::redact_json_differently(json, Some("event_properties"));
	redact::redact_json_differently(json, Some("user_properties"));
	let mut event = match Event::from_json(json.clone()) {
		Err(e) => {
			panic!("Amplitude event not well-formed: {e}");
		},
		Ok(e) => e,
	};

	// Clean up anything else left
	redact::redact_json(json);

	// Remove consumer device identificators
	redact::redact_key(json, "idfa");
	redact::redact_key(json, "idfv");
	redact::redact_key(json, "adid");
	redact::redact_key(json, "android_id");

	// REDACT ID of event w/ID of proxy
	event.user_id(std::env::var("NAIS_CLIENT_ID").unwrap_or(env!("CARGO_PKG_NAME").to_string()));

	// Add back in upstream required (non-redacted) fields/keys
	event.event_type(event_type);
	serde_json::to_value(event).expect("Processed Amplitude event is not well-formed JSON")
}

#[cfg(test)]
mod tests {
	use super::*;
}
