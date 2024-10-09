use serde_json::Value;

use crate::k8s;

pub fn annotate_with_proxy_version(event: &mut Value, proxy_version: &str) {
	if let Value::Object(map) = event {
		map.insert(
			"proxyVersion".to_string(),
			Value::String(proxy_version.to_string()),
		);
	}
}

// some of these
// [Amplitude] City, [Amplitude] DMA, [Amplitude] Region, and [Amplitude] Country
pub fn annotate_with_location(value: &mut Value, city: &String, country: &String) {
	match value {
		Value::Array(arr) => {
			for v in arr {
				annotate_with_location(v, city, country);
			}
		},
		Value::Object(obj) => {
			for (key, v) in obj.iter_mut() {
				if key == "event_properties" && v.is_object() {
					v.as_object_mut()
						.unwrap()
						.insert("[Amplitude] City".into(), Value::String(city.to_owned()));
					v.as_object_mut().unwrap().insert(
						"[Amplitude] Country".into(),
						Value::String(country.to_owned()),
					);
				}
			}
		},

		_ => {
			// No need to do anything for these types
		},
	}
}

pub fn annotate_with_app_info(value: &mut Value, app_info: &k8s::cache::AppInfo) {
	match value {
		Value::Array(arr) => {
			for v in arr {
				annotate_with_app_info(v, &app_info.clone());
			}
		},
		Value::Object(obj) => {
			for (key, v) in obj.iter_mut() {
				if key == "event_properties" && v.is_object() {
					v.as_object_mut()
						.unwrap()
						.insert("team".into(), app_info.namespace.clone().into());
					v.as_object_mut()
						.unwrap()
						.insert("ingress".into(), app_info.ingress.clone().into());
					v.as_object_mut()
						.unwrap()
						.insert("app".into(), app_info.app.clone().into());
				}
			}
		},

		_ => {
			// No need to do anything for these types
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn test_annotate_with_location() {
		let mut event = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue"
			},
			"session_id": 16789
		});

		annotate_with_location(&mut event, &"New York".to_string(), &"USA".to_string());

		let expected_event = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"[Amplitude] City": "New York",
				"[Amplitude] Country": "USA"
			},
			"session_id": 16789
		});

		assert_eq!(event, expected_event);
	}

	#[test]
	fn test_annotate_with_location_existing_location() {
		let mut event = json!({
			"user_id": "12345",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"[Amplitude] City": "Los Angeles",
				"[Amplitude] Country": "Canada"
			}
		});

		annotate_with_location(&mut event, &"New York".to_string(), &"USA".to_string());

		let expected_event = json!({
			"user_id": "12345",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue",
				"[Amplitude] City": "New York",
				"[Amplitude] Country": "USA"
			}
		});

		assert_eq!(event, expected_event);
	}
	#[test]
	fn test_annotate_with_proxy_version() {
		let mut event = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue"
			},
			"session_id": 16789
		});

		annotate_with_proxy_version(&mut event, "1.2.3");

		let expected_event = json!({
			"user_id": "12345",
			"device_id": "device-98765",
			"event_type": "button_click",
			"event_properties": {
				"button_name": "signup_button",
				"color": "blue"
			},
			"session_id": 16789,
			"proxyVersion": "1.2.3"  // The new field added
		});

		assert_eq!(event, expected_event);
	}

	#[test]
	fn test_annotate_proxy_version_overwrite() {
		let mut event = json!({
			"user_id": "12345",
			"proxyVersion": "1.0.0"
		});

		annotate_with_proxy_version(&mut event, "2.0.0");

		let expected_event = json!({
			"user_id": "12345",
			"proxyVersion": "2.0.0"  // The field should be updated to 2.0.0
		});

		assert_eq!(event, expected_event);
	}
}
