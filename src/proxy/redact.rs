use http::Uri;
use regex::Regex;
use serde_json::{Number, Value};
use std::collections::HashMap as Map;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tra {
	Redacted,           // Replace with the string [Redacted]
	Removed,            // Replace with null
	Kept(String),       // string
	Original(String),   // String
	Annotated(String),  // String
	GeoLocated(String), // Several fields!
}

/// This is a nonserializeable(sic!) Json with redact leaf nodes
pub enum Transform {
	Null,
	Bool(bool),
	Number(Number),
	String(String),
	Transform(Tra),
	Array(Vec<Transform>),
	Object(Map<String, Transform>), // Maybe there should be a note on the keys too?
}

impl Tra {
	pub(crate) fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::Redacted => redacted.to_string(),
			Self::Kept(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
			Self::Annotated(s) => s.to_string(),
			Self::Removed => "".to_string(),
			_ => "".to_string(),
		}
	}
	pub(crate) fn new(s: &str) -> Self {
		redact(s)
	}
}

/// Goes from Value to Redact, This is an entrypoint to making redacted Value
/// Note that there's no usage of Transform constructors here.
pub fn value_to_transform(value: Value) -> Transform {
	match value {
		Value::Null => Transform::Null,
		Value::Bool(b) => Transform::Bool(b),
		Value::Number(n) => Transform::Number(n),
		Value::String(s) => Transform::String(s),
		Value::Array(arr) => {
			let transformed_array = arr.into_iter().map(value_to_transform).collect();
			Transform::Array(transformed_array)
		},
		Value::Object(map) => {
			let transformed_map = map
				.into_iter()
				.map(|(k, v)| (k, value_to_transform(v)))
				.collect();
			Transform::Object(transformed_map)
		},
	}
}

pub fn transform_to_value<F>(transform: Transform, handler: F) -> Value
where
	F: Fn(Tra) -> Value, // Handler for TransformType nodes
{
	match transform {
		Transform::Null => Value::Null,
		Transform::Bool(b) => Value::Bool(b),
		Transform::Number(n) => Value::Number(n),
		Transform::String(s) => Value::String(s),
		Transform::Array(arr) => {
			let json_array: Vec<Value> = arr
				.into_iter()
				.map(|item| transform_to_value(item, &handler))
				.collect();
			Value::Array(json_array)
		},
		Transform::Object(map) => {
			let json_object: serde_json::Map<String, Value> = map
				.into_iter()
				.map(|(k, v)| (k, transform_to_value(v, &handler)))
				.collect();
			Value::Object(json_object)
		},

		// Leaf nodes get >>Handled<< Here. This could be made explicit, we don't need pluggable handlers
		Transform::Transform(t) => handler(t),
	}
}

fn redact(s: &str) -> Tra {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		Tra::Kept(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		Tra::Redacted
	} else {
		Tra::Original(s.to_string())
	}
}

fn print_query((key, value): &(Tra, Tra)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

fn redact_paths(ps: &[&str]) -> Vec<Tra> {
	ps.iter().map(|p: &&str| Tra::new(p)).collect()
}

fn redact_queries(ss: &[(&str, &str)]) -> Vec<(Tra, Tra)> {
	ss.iter().map(|q| (Tra::new(q.0), Tra::new(q.1))).collect()
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

/// Redacts location-related fields in a `Transform` tree and returns a new `Transform`.
pub fn redact_location(value: Transform) -> Transform {
	match value {
		Transform::Object(map) => {
			let redacted_map = map
				.into_iter()
				.map(|(k, v)| {
					if k == "location_lat" || k == "location_lng" || k == "ip_address" {
						(k, Transform::Transform(Tra::Removed))
					} else {
						(k, redact_location(v))
					}
				})
				.collect();
			Transform::Object(redacted_map)
		},
		Transform::Array(arr) => {
			let redacted_array = arr.into_iter().map(redact_location).collect();
			Transform::Array(redacted_array)
		},
		other => other,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use assert_json_diff::assert_json_include;
	use serde_json::json;

	#[test]
	fn test_redact_location_in_amplitude_event() {
		// TODO
	}

	#[test]
	fn test_redact_uuid_in_amplitude_event() {
		// TODO
	}

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input);
		assert_eq!(result, Tra::Kept(input.to_string()));
		let input = "test654321";
		let result = redact(input);
		assert_eq!(result, Tra::Kept(input.to_string()));
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input);
		assert_eq!(result, Tra::Redacted);
		let input = "1ABCD23456789";
		let result = redact(input);
		assert_eq!(result, Tra::Redacted);
		let input = "123456";
		let result = redact(input);
		assert_eq!(result, Tra::Redacted);
		let input = "a1b2c3d4e5";
		let result = redact(input);
		assert_eq!(result, Tra::Redacted);
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input);
		assert_eq!(result, Tra::Original(input.to_string()));
		let input = "anotherString";
		let result = redact(input);
		assert_eq!(result, Tra::Original(input.to_string()));
		let input = "12345";
		let result = redact(input);
		assert_eq!(result, Tra::Original(input.to_string()));
	}
}
