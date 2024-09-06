use http::Uri;
use regex::Regex;
use serde_json::{Map, Number, Value};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Transform {
	Redacted,
	Keep(String),
	Original(String),
	Annotated(String),
	IpTransform(String),
}

/// This is a nonserializeable Json with redact leaves
pub enum Redact {
	Null,
	Bool(bool),
	Number(Number),
	String(String),
	Transform(Transform),
	Array(Vec<Transform>),
	Object(Map<String, Transform>),
}

// //       serde_json::Value
// pub enum Serde_Json__Value {
// 	Null,
// 	Bool(bool),
// 	Number(Number),
// 	String(String),
//         Transform,
// 	Array(Vec<Serde_Json__Value>),
// 	Object(Map<String, Serde_Json__Value>),
// }

// // Todo, Bytes -> serde_json::Value -1> Redact -2> Value -> Bytes
// // this is -2>
// fn josnify(v: Redact) -> Serde_Json__Value {
//     match v {
//         Redact::Null => Serde_Json__Value::Null,
//         Redact::Bool(x) => Serde_Json__Value::Bool(x),
//             Redact::Number(n) => Serde_Json__Value::Number(n),
//         Redact::String(s) => Serde_Json__Value::String(s),
//         Redact::Transform(transform) => matchTransform(transform) //(Transform) -> Value
//         Redact::Array(a) => a.iter.foreach()
//         Redact::Object(m) => m.iter.foreach(|k,v| =
//             if k == "some key" {

//             }
//         )

//     }
// }

// // this is -1>
// fn redact(v: Serde_Json__Value) -> Redact {
// match sjv
//        Serde_Json__Value::Null => Null
//        Serde_Json__Value::Bool(bool) => Bool(bool)
//        Serde_Json__Value::Number(Number) => Number(Number)
//        Serde_Json__Value::String(String) => redact(String) (: String -> Redact)
//            Serde_Json__Value::Array(vec) => vec.iter.map.redact.collect()
//        Serde_Json__Value::Object(map) =>
//            map.iter.map(|k,v|  {
//                if key == "cool-key"

//            })

//                }

impl Transform {
	pub(crate) fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::Redacted => redacted.to_string(),
			Self::Keep(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
			Self::Annotated(s) => s.to_string(),
		}
	}
	pub(crate) fn new(s: &str) -> Self {
		redact(s)
	}
}

fn redact(s: &str) -> Transform {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		Transform::Keep(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		Transform::Redacted
	} else {
		Transform::Original(s.to_string())
	}
}

fn print_query((key, value): &(Transform, Transform)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<Transform> {
	ps.iter().map(|p: &&str| Transform::new(p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(Transform, Transform)> {
	ss.iter()
		.map(|q| (Transform::new(q.0), Transform::new(q.1)))
		.collect()
}

pub fn redact_uri(old_uri: &Uri) -> Uri {
	let redacted_paths = itertools::join(
		redact_paths(&old_uri.path().split('/').collect::<Vec<_>>())
			.iter()
			.map(|x| x.pretty_print()),
		"/",
	);

	let redacted_queries = itertools::join(
		redact_queries(
			&old_uri
				.query()
				.unwrap_or("")
				.split('&')
				.flat_map(|q| q.split_once('='))
				.collect::<Vec<_>>(),
		)
		.iter()
		.map(print_query),
		"&",
	);

	let new_uri = format!("{redacted_paths}?{redacted_queries}")
		.parse::<Uri>()
		.unwrap();
	dbg!(&new_uri);
	new_uri
}
/// Redacts location data and ip  by setting them to null.
pub fn redact_location(value: &mut Value) {
	match value {
		Value::Object(map) => {
			if let Some(loc_lat) = map.get_mut("location_lat") {
				*loc_lat = Value::Null;
			}
			if let Some(loc_lng) = map.get_mut("location_lng") {
				*loc_lng = Value::Null;
			}
			if let Some(ip_address) = map.get_mut("ip_address") {
				*ip_address = Value::Null;
			}
			for (_, v) in map.iter_mut() {
				redact_location(v);
			}
		},

		Value::Array(arr) => {
			for item in arr.iter_mut() {
				redact_location(item);
			}
		},
		_ => { // We cant redact Bools etc.
		},
	}
}

pub fn redact_json(value: &mut Value) {
	match value {
		Value::String(s) => {
			*s = redact(s).pretty_print();
		},
		Value::Array(arr) => {
			for v in arr {
				redact_json(v);
			}
		},
		Value::Object(obj) => {
			for (_, v) in obj.iter_mut() {
				redact_json(v);
			}
		},
		_ => {
			// (Number, Bool, Null), do not need redacting (?)
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use assert_json_diff::assert_json_include;
	use serde_json::json;

	#[test]
	fn test_redact_location_in_amplitude_event() {
		let mut json_data = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue"
			},
			"user_properties": {
				"age": 30,
				"gender": "female"
			},
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89",
			"session_id": 16789,
			"nested_object": { // Just too have this too. Real events dont do nested objects
				"location_lat": 48.8566,
				"location_lng": 2.3522,
				"ip_address": "98.76.54.32"
			}
		});

		// Apply the redaction function
		redact_location(&mut json_data);

		// Expected JSON after redaction, where location fields are null
		let expected_data = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue"
			},
			"user_properties": {
				"age": 30,
				"gender": "female"
			},
			"location_lat": null,
			"location_lng": null,
			"ip_address": null,
			"session_id": 16789,
			"nested_object": {
				"location_lat": null,
				"location_lng": null,
				"ip_address": null
			}
		});

		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_redact_uuid_in_amplitude_event() {
		let uuid = "123e4567-e89b-12d3-a456-426614174000";

		let mut json_data = json!({
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
			"event_time": 5,
			"session_id": 5,
			"insert_id": uuid,  // <-- This guy
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		let expected_data = json!({
			"user_id": "12345",
			"device_id": "[redacted]",
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
			"event_time": 5,
			"session_id": 5,
			"insert_id": "[redacted]",
			"location_lat": 37.7749,
			"location_lng": -122.4194,
			"ip_address": "123.45.67.89"
		});

		redact_json(&mut json_data);

		assert_eq!(json_data, expected_data);
	}

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input);
		assert_eq!(result, Transform::Keep(input.to_string()));
		let input = "test654321";
		let result = redact(input);
		assert_eq!(result, Transform::Keep(input.to_string()));
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input);
		assert_eq!(result, Transform::Redacted);
		let input = "1ABCD23456789";
		let result = redact(input);
		assert_eq!(result, Transform::Redacted);
		let input = "123456";
		let result = redact(input);
		assert_eq!(result, Transform::Redacted);
		let input = "a1b2c3d4e5";
		let result = redact(input);
		assert_eq!(result, Transform::Redacted);
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input);
		assert_eq!(result, Transform::Original(input.to_string()));
		let input = "anotherString";
		let result = redact(input);
		assert_eq!(result, Transform::Original(input.to_string()));
		let input = "12345";
		let result = redact(input);
		assert_eq!(result, Transform::Original(input.to_string()));
	}

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

pub fn redact_key(json: &mut Value, key: &str) {
	if let Some(j) = json.get_mut(key) {
		j.take();
	}
}

pub fn redact_json_differently(json: &mut Value, key: Option<&str>) {
	match key {
		Some(k) => {
			if let Some(j) = json.get_mut(k) {
				redact_json(j)
			}
		},
		None => redact_json(json),
	}
}

/// This function does all the manipulation/treatment of the HTTP request body received from some browser's amplitude sdk
/// 1. Parse JSON as some version of an Amplitude event; TODO: Check/handle multiple versions?
///    - NB: `amplitude::Event`'s serde implementation lossly ignores any fields
/// 		not existing over @ https://amplitude.com/docs/apis/analytics/http-v2#schemaevent
/// 1. Replace (coarsen) downstream IP w/(coarse) geo data; TODO
/// 1. Set `ProxyVersion` to name of this app (so we @ NAV can identify where the Amplitude event came from over @ Amplitude)
/// 1. Use the `crate::proxy::redact` module's logic to redact any data inside `(event|user)_properties` of the event body
pub fn process_event(json: &mut Value) -> Value {
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
	redact_json_differently(json, Some("event_properties"));
	redact_json_differently(json, Some("user_properties"));
	// let mut event = match Event::from_json(json.clone()) {
	// 	Err(e) => {
	// 		panic!("Amplitude event not well-formed: {e}");
	// 	},
	// 	Ok(e) => e,
	// };
	// Clean up anything else left
	redact_json(json);

	// Remove consumer device identificators
	redact_key(json, "idfa");
	redact_key(json, "idfv");
	redact_key(json, "adid");
	redact_key(json, "android_id");

	// REDACT ID of event w/ID of proxy
	// TODO this should just use Value
	// event.user_id(std::env::var("NAIS_CLIENT_ID").unwrap_or(env!("CARGO_PKG_NAME").to_string()));

	// Add back in upstream required (non-redacted) fields/keys
	// TODO: this should just use Value
	//	event.event_type(event_type);
	json.clone()
}
