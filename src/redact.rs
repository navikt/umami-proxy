use regex::{Regex, RegexBuilder};

// keep
const KEEP_REGEX: &str = r#"/(nav|test)[0-9]{6}"#;

// redact
const HEX_REGEX: &str = r#"/[a-f0-9\-]{6,}"#;
const ID_REGEX: &str = r#"/\d[oiA-Z0-9]{8,}"#;

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
			RedactType::RedactValue => redacted.to_string(),
			RedactType::Keep(s) => s.to_string(),
			RedactType::Original(s) => s.to_string(),
		}
	}
	pub fn new(s: &str) -> RedactType {
		let original_string = s.to_string();

		// We "keep"
		let keepexe = Regex::new(KEEP_REGEX).expect("Unable to compile keepex regex");
		if keepexe.is_match(&original_string) {
			dbg!("kept");
			return RedactType::Keep(original_string.to_string());
		}

		// We redact based on hex pattern
		let hexexe = RegexBuilder::new(HEX_REGEX)
			.case_insensitive(true)
			.build()
			.expect("Unable to compile hex regex");
		if hexexe.is_match(&original_string) {
			dbg!("redact! hex");
			return RedactType::RedactValue;
		}

		// We redact based on ID pattern
		let idexe = Regex::new(ID_REGEX).expect("Unable to compile id regex");
		if idexe.is_match(&original_string) {
			dbg!("redact index!");
			return RedactType::RedactValue;
		}

		// If none of the patterns match, return the original string
		RedactType::Original(original_string)
	}
}

pub fn print_query((key, value): &(RedactType, RedactType)) -> String {
	format!("{}={}", key.pretty_print(), value.pretty_print())
}

pub fn redact_paths(ps: &[&str]) -> Vec<RedactType> {
	ps.iter().map(|p: &&str| RedactType::new(*p)).collect()
}

pub fn redact_queries(ss: &[(&str, &str)]) -> Vec<(RedactType, RedactType)> {
	ss.iter()
		.map(|q| (RedactType::new(q.0), RedactType::new(q.1)))
		.collect()
}

#[cfg(test)]
mod test {
	use super::*;
	#[test]
	fn test_nav() {
		let t = "nav123456";
		assert_eq!(RedactType::Keep(t.to_string()), RedactType::new(t));
	}
	#[test]
	fn test_test() {
		let t = "test123456";
		assert_eq!(RedactType::Keep(t.to_string()), RedactType::new(t));
	}
	#[test]
	fn test_hex() {
		let t = "f6338366-64a5-44a7-8459-6cbf17a57343";
		assert_eq!(RedactType::RedactValue, RedactType::new(t));
	}

	#[test]
	fn test_id() {
		let t = "12o798324i";
		assert_eq!(RedactType::RedactValue, RedactType::new(t));
	}

	#[test]
	fn test_norm() {
		let t = "quick brown fox jumped over the lazy dog";
		assert_eq!(RedactType::Original(t.to_string()), RedactType::new(t));
	}
}
