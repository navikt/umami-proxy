use regex::Regex;
use serde_json::{Map, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum RedactType {
	RedactValue,
	Keep(String),
	Original(String),
}

impl RedactType {
	pub fn pretty_print(&self) -> String {
		let redacted = "[redacted]";
		match self {
			Self::RedactValue => redacted.to_string(),
			Self::Keep(s) => s.to_string(),
			Self::Original(s) => s.to_string(),
		}
	}
	pub fn new(s: &str) -> Self {
		redact(s)
	}
}

pub fn redact(s: &str) -> RedactType {
	let keep_regex = Regex::new(r"(nav|test)[0-9]{6}").unwrap();
	let hex_regex = Regex::new(r"[a-f0-9\-]{6,}").unwrap();
	let id_regex = Regex::new(r"\d[oiA-Z0-9]{8,}").unwrap();

	if keep_regex.is_match(s) {
		RedactType::Keep(s.to_string())
	} else if hex_regex.is_match(s) || id_regex.is_match(s) {
		RedactType::RedactValue
	} else {
		RedactType::Original(s.to_string())
	}
}

pub fn print_query((key, value): &(RedactType, RedactType)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

pub fn redact_paths(ps: &[&str]) -> Vec<RedactType> {
	ps.iter().map(|p: &&str| RedactType::new(p)).collect()
}

pub fn redact_queries(ss: &[(&str, &str)]) -> Vec<(RedactType, RedactType)> {
	ss.iter()
		.map(|q| (RedactType::new(q.0), RedactType::new(q.1)))
		.collect()
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

	#[test]
	fn test_keep_regex() {
		let input = "nav123456";
		let result = redact(input);
		assert_eq!(result, RedactType::Keep(input.to_string()));

		let input = "test654321";
		let result = redact(input);
		assert_eq!(result, RedactType::Keep(input.to_string()));
	}

	#[test]
	fn test_redact_regex() {
		let input = "abcdef123456";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "1ABCD23456789";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "123456";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);

		let input = "a1b2c3d4e5";
		let result = redact(input);
		assert_eq!(result, RedactType::RedactValue);
	}

	#[test]
	fn test_original_regex() {
		let input = "regularstring";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));

		let input = "anotherString";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));

		let input = "12345";
		let result = redact(input);
		assert_eq!(result, RedactType::Original(input.to_string()));
	}
}
