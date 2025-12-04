use once_cell::sync::Lazy;
use regex::Regex;

/// Privacy check patterns for detecting potentially sensitive data
/// These patterns are used to scan analytics data for Norwegian personal information
pub static PRIVACY_PATTERNS: Lazy<Vec<PrivacyPattern>> = Lazy::new(|| {
	vec![
		// Norwegian National ID Number (11 digits)
		PrivacyPattern {
			name: "Fødselsnummer",
			redaction_label: "PROXY-FNR",
			regex: Regex::new(r"\b\d{11}\b").unwrap(),
		},
		// NAV identifier (letter followed by 6 digits)
		PrivacyPattern {
			name: "Navident",
			redaction_label: "PROXY-NAVIDENT",
			regex: Regex::new(r"\b[a-zA-Z]\d{6}\b").unwrap(),
		},
		// Email address
		PrivacyPattern {
			name: "E-post",
			redaction_label: "PROXY-EMAIL",
			regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
		},
		// IP address
		PrivacyPattern {
			name: "IP-adresse",
			redaction_label: "PROXY-IP",
			regex: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
		},
		// Phone number (8 digits starting with 2-9) - simplified without lookbehind
		PrivacyPattern {
			name: "Telefonnummer",
			redaction_label: "PROXY-PHONE",
			regex: Regex::new(r"\b[2-9]\d{7}\b").unwrap(),
		},
		// Possible name (Norwegian characters, 2-3 capitalized words)
		PrivacyPattern {
			name: "Mulig navn",
			redaction_label: "PROXY-NAME",
			regex: Regex::new(
				r"\b[A-ZÆØÅ][a-zæøå]{1,20}\s[A-ZÆØÅ][a-zæøå]{1,20}(?:\s[A-ZÆØÅ][a-zæøå]{1,20})?\b",
			)
			.unwrap(),
		},
		// Possible address (4 digits followed by capitalized words)
		PrivacyPattern {
			name: "Mulig adresse",
			redaction_label: "PROXY-ADDRESS",
			regex: Regex::new(r"\b\d{4}\s[A-ZÆØÅ][A-ZÆØÅa-zæøå]+(?:\s[A-ZÆØÅa-zæøå]+)*\b").unwrap(),
		},
		// Secret address (case-insensitive, handles URL encoding)
		PrivacyPattern {
			name: "Hemmelig adresse",
			redaction_label: "PROXY-SECRET-ADDRESS",
			regex: Regex::new(r"(?i)hemmelig(?:%20|\s+)(?:20\s*%(?:%20|\s+))?adresse").unwrap(),
		},
		// Bank account number (Norwegian format: 4.2.5 digits)
		PrivacyPattern {
			name: "Kontonummer",
			redaction_label: "PROXY-ACCOUNT",
			regex: Regex::new(r"\b\d{4}\.?\d{2}\.?\d{5}\b").unwrap(),
		},
		// Organization number (9 digits)
		PrivacyPattern {
			name: "Organisasjonsnummer",
			redaction_label: "PROXY-ORG-NUMBER",
			regex: Regex::new(r"\b\d{9}\b").unwrap(),
		},
		// License plate (2 letters followed by 5 digits)
		PrivacyPattern {
			name: "Bilnummer",
			redaction_label: "PROXY-LICENSE-PLATE",
			regex: Regex::new(r"\b[A-Z]{2}\s?\d{5}\b").unwrap(),
		},
		// Possible search query (URL query parameters)
		PrivacyPattern {
			name: "Mulig søk",
			redaction_label: "PROXY-SEARCH",
			regex: Regex::new(r"[?&](?:q|query|search|k|ord)=[^&]+").unwrap(),
		},
	]
});

/// Represents a privacy pattern with its regex and redaction label
pub struct PrivacyPattern {
	pub name: &'static str,
	pub redaction_label: &'static str,
	pub regex: Regex,
}

/// Redacts PII from a string by applying all privacy patterns
/// Returns the redacted string
pub fn redact_pii(input: &str) -> String {
	let mut result = input.to_string();

	for pattern in PRIVACY_PATTERNS.iter() {
		if pattern.regex.is_match(&result) {
			result = pattern
				.regex
				.replace_all(&result, format!("[{}]", pattern.redaction_label))
				.to_string();
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_redact_email() {
		let input = "Contact: user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "Contact: [PROXY-EMAIL]");
	}

	#[test]
	fn test_redact_fodselsnummer() {
		let input = "SSN: 12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "SSN: [PROXY-FNR]");
	}

	#[test]
	fn test_redact_phone_number() {
		let input = "Call me at 98765432";
		let result = redact_pii(input);
		assert_eq!(result, "Call me at [PROXY-PHONE]");
	}

	#[test]
	fn test_redact_navident() {
		let input = "User: X123456";
		let result = redact_pii(input);
		assert_eq!(result, "User: [PROXY-NAVIDENT]");
	}

	#[test]
	fn test_redact_ip_address() {
		let input = "IP: 192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "IP: [PROXY-IP]");
	}

	#[test]
	fn test_redact_bank_account() {
		let input = "Account: 1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "Account: [PROXY-ACCOUNT]");
	}

	#[test]
	fn test_redact_multiple_patterns() {
		let input = "Email user@test.com with phone 98765432";
		let result = redact_pii(input);
		assert_eq!(result, "Email [PROXY-EMAIL] with phone [PROXY-PHONE]");
	}

	#[test]
	fn test_no_redaction_needed() {
		let input = "This is a normal string with no PII";
		let result = redact_pii(input);
		assert_eq!(result, input);
	}

	#[test]
	fn test_redact_secret_address() {
		let input = "hemmelig adresse";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-SECRET-ADDRESS]");
	}

	#[test]
	fn test_redact_license_plate() {
		let input = "Plate: AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "Plate: [PROXY-LICENSE-PLATE]");
	}

	#[test]
	fn test_redact_org_number() {
		let input = "Org: 123456789";
		let result = redact_pii(input);
		assert_eq!(result, "Org: [PROXY-ORG-NUMBER]");
	}
}
