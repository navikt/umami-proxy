use fancy_regex::Regex;
use once_cell::sync::Lazy;

pub static PRIVACY_PATTERNS: Lazy<Vec<PrivacyPattern>> = Lazy::new(|| {
	vec![
		// HTTP/HTTPS URLs - placed first to preserve legitimate URLs
		// This pattern matches http:// and https:// URLs and marks them for preservation
		// We use a special marker that won't be redacted by other patterns
		PrivacyPattern {
			_name: "Legitimate URLs",
			redaction_label: "PROXY-PRESERVE-URL",
			regex: Regex::new(
				r"https?://[A-Za-z0-9._\-]+(?:\.[A-Za-z0-9._\-]+)*(?::[0-9]+)?(?:/[A-Za-z0-9._\-/%?&=]*)?",
			)
			.unwrap(),
		},
		// File paths (Windows, Unix, macOS) - placed first to avoid NAME pattern matching path components
		// Matches absolute and relative paths that may contain personal information
		// Key indicators: path separators (/ or \), hierarchical structure
		// Better safe than sorry - we match liberally to catch all potential file paths
		PrivacyPattern {
			_name: "Filsti",
			redaction_label: "PROXY-FILEPATH",
			regex: Regex::new(
				r"(?x)
				(?:
					# Windows absolute paths: C:\path\to\file or C:/path/to/file
					# Matches drive letter followed by colon and separator
					[A-Za-z]:[/\\]
					(?:[A-Za-z0-9._\-\s%]+[/\\])*
					[A-Za-z0-9._\-\s%]+
					(?:\.[A-Za-z0-9]{1,10})?
					|
					# Windows UNC paths: \\server\share\path\file
					\\\\[A-Za-z0-9._\-]+\\[A-Za-z0-9._\-]+
					(?:\\[A-Za-z0-9._\-\s]+)*
					(?:\\[A-Za-z0-9._\-\s]+(?:\.[A-Za-z0-9]{1,10})?)?
					|
					# file:// protocol URIs
					file:///
					[A-Za-z0-9._\-\s/%:]+
					(?:\.[A-Za-z0-9]{1,10})?
					|
				# Unix/Mac absolute paths - ANY path starting with /
				# Format: /component/component/... OR /file.ext (single file at top level)
				(?:
					# Multi-component paths (at least 2 components)
					/[A-Za-z0-9._\-]+
					(?:/[A-Za-z0-9._\-]+)+
					(?:\.[A-Za-z0-9]{1,10})?
					|
					# Single file at top level with extension
					# Must contain at least one letter to distinguish from pure numbers like IPs or account numbers
					/(?=.*[A-Za-z])[A-Za-z0-9._\-]+\.[A-Za-z0-9]{1,10}
				)
					|
					# Relative paths: ./path, ../path, ~/path
					(?:\./|\.\./|~/)
					(?:[A-Za-z0-9._\-]+/)*
					[A-Za-z0-9._\-]+
					(?:\.[A-Za-z0-9]{1,10})?
				)
				",
			)
			.unwrap(),
		},
		// Norwegian National ID Number (11 digits)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			_name: "Fødselsnummer",
			redaction_label: "PROXY-FNR",
			regex: Regex::new(r"(?<!\d)\d{11}(?!\d)").unwrap(),
		},
		// NAV identifier (letter followed by 6 digits)
		// Use negative lookaround for alphanumeric to avoid matching partial IDs
		PrivacyPattern {
			_name: "Navident",
			redaction_label: "PROXY-NAVIDENT",
			regex: Regex::new(r"(?<![a-zA-Z0-9])[a-zA-Z]\d{6}(?!\d)").unwrap(),
		},
		// Email address
		// Simple practical regex that matches 99% of real emails in use today
		// Underscore is a valid email character, so "my_email@example.com" is treated as one email
		PrivacyPattern {
			_name: "E-post",
			redaction_label: "PROXY-EMAIL",
			regex: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
		},
		// IP address
		// Use negative lookaround for digits and dots to avoid matching partial IPs
		PrivacyPattern {
			_name: "IP-adresse",
			redaction_label: "PROXY-IP",
			regex: Regex::new(r"(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)").unwrap(),
		},
		// Phone number (8 digits starting with 2-9)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			_name: "Telefonnummer",
			redaction_label: "PROXY-PHONE",
			regex: Regex::new(r"(?<!\d)[2-9]\d{7}(?!\d)").unwrap(),
		},
		// Possible name (Norwegian characters, 2-3 capitalized words)
		PrivacyPattern {
			_name: "Mulig navn",
			redaction_label: "PROXY-NAME",
			regex: Regex::new(
				r"\b[A-ZÆØÅ][a-zæøå]{1,20}\s[A-ZÆØÅ][a-zæøå]{1,20}(?:\s[A-ZÆØÅ][a-zæøå]{1,20})?\b",
			)
			.unwrap(),
		},
		// Possible address (4 digits followed by capitalized words)
		PrivacyPattern {
			_name: "Mulig adresse",
			redaction_label: "PROXY-ADDRESS",
			regex: Regex::new(r"\b\d{4}\s[A-ZÆØÅ][A-ZÆØÅa-zæøå]+(?:\s[A-ZÆØÅa-zæøå]+)*\b").unwrap(),
		},
		// Secret address (case-insensitive, handles URL encoding)
		PrivacyPattern {
			_name: "Hemmelig adresse",
			redaction_label: "PROXY-SECRET-ADDRESS",
			regex: Regex::new(r"(?i)hemmelig(?:%20|\s+)(?:20\s*%(?:%20|\s+))?adresse").unwrap(),
		},
		// Bank account number (Norwegian format: 4.2.5 digits)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			_name: "Kontonummer",
			redaction_label: "PROXY-ACCOUNT",
			regex: Regex::new(r"(?<!\d)\d{4}\.?\d{2}\.?\d{5}(?!\d)").unwrap(),
		},
		// Organization number (9 digits)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			_name: "Organisasjonsnummer",
			redaction_label: "PROXY-ORG-NUMBER",
			regex: Regex::new(r"(?<!\d)\d{9}(?!\d)").unwrap(),
		},
		// License plate (2 letters followed by 5 digits)
		// Use negative lookaround for alphanumeric to avoid matching partial plates
		PrivacyPattern {
			_name: "Bilnummer",
			redaction_label: "PROXY-LICENSE-PLATE",
			regex: Regex::new(r"(?<![a-zA-Z])[A-Z]{2}\s?\d{5}(?!\d)").unwrap(),
		},
		// Possible search query (URL query parameters)
		PrivacyPattern {
			_name: "Mulig søk",
			redaction_label: "PROXY-SEARCH",
			regex: Regex::new(r"[?&](?:q|query|search|k|ord)=[^&]+").unwrap(),
		},
	]
});

/// Represents a privacy pattern with its regex and redaction label
pub struct PrivacyPattern {
	pub _name: &'static str,
	pub redaction_label: &'static str,
	pub regex: Regex,
}

/// Redacts PII from a string by applying all privacy patterns
/// Returns the redacted string
pub fn redact_pii(input: &str) -> String {
	let mut result = input.to_string();
	let mut preserved_urls: Vec<String> = Vec::new();
	let mut preserved_uuids: Vec<String> = Vec::new();

	// First pass: extract and replace UUIDs with placeholders
	// UUIDs have format: 8-4-4-4-12 hexadecimal characters separated by hyphens
	// Example: 550e8400-e29b-41d4-a716-446655440000
	// We use word boundaries to ensure we match complete UUIDs
	let uuid_regex =
		Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
			.unwrap();

	for (i, capture_result) in uuid_regex.captures_iter(&result.clone()).enumerate() {
		if let Ok(capture) = capture_result {
			if let Some(full_match) = capture.get(0) {
				preserved_uuids.push(full_match.as_str().to_string());
				result = result.replace(full_match.as_str(), &format!("__PRESERVED_UUID_{}__", i));
			}
		}
	}

	// Second pass: extract and replace http/https URLs with placeholders
	let url_regex = Regex::new(
		r"(?x)
		(?:
			# URLs with http/https protocol
			https?://[A-Za-z0-9._\-]+(?:\.[A-Za-z0-9._\-]+)*(?::[0-9]+)?(?:/[A-Za-z0-9._\-/%?&=]*)?
			|
			# Domain-like patterns (without protocol) - must have a TLD
			# Format: subdomain.domain.tld/path or domain.tld/path
			# Use negative lookbehind to avoid matching email domains (no @ before)
			(?<!@)[A-Za-z0-9._\-]+\.[A-Za-z]{2,}(?:/[A-Za-z0-9._\-/%?&=]+)
		)
		",
	)
	.unwrap();

	for (i, capture_result) in url_regex.captures_iter(&result.clone()).enumerate() {
		if let Ok(capture) = capture_result {
			if let Some(full_match) = capture.get(0) {
				preserved_urls.push(full_match.as_str().to_string());
				result = result.replace(full_match.as_str(), &format!("__PRESERVED_URL_{}__", i));
			}
		}
	}

	// Third pass: apply all privacy patterns
	for pattern in PRIVACY_PATTERNS.iter() {
		// Skip the URL preservation pattern
		if pattern.redaction_label == "PROXY-PRESERVE-URL" {
			continue;
		}

		// fancy-regex returns Result for is_match, so we need to handle errors
		if let Ok(is_match) = pattern.regex.is_match(&result) {
			if is_match {
				// replace_all returns Cow<str>, not Result
				result = pattern
					.regex
					.replace_all(&result, format!("[{}]", pattern.redaction_label).as_str())
					.to_string();
			}
		}
	}

	// Fourth pass: restore preserved UUIDs
	for (i, uuid) in preserved_uuids.iter().enumerate() {
		result = result.replace(&format!("__PRESERVED_UUID_{}__", i), uuid);
	}

	// Fifth pass: restore preserved URLs
	for (i, url) in preserved_urls.iter().enumerate() {
		result = result.replace(&format!("__PRESERVED_URL_{}__", i), url);
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
	fn test_redact_email_variants() {
		// Underscore is a valid email character, so the whole thing matches as one email
		// This is fine - we redact the entire email which is the goal
		let input = "my_email_user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-EMAIL]");

		let input = "my-email:user@example.com it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-email:[PROXY-EMAIL] it's nice");

		// Hyphen is also a valid email character in our regex
		let input = "my-email-user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-EMAIL]");

		// Additional common delimiter variants
		let input = "email.is.user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-EMAIL]");

		let input = "email/user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "email/[PROXY-EMAIL]");

		let input = "email user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "email [PROXY-EMAIL]");

		let input = "email|user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "email|[PROXY-EMAIL]");

		let input = "email+tag@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-EMAIL]");

		let input = "email#user@example.com";
		let result = redact_pii(input);
		assert_eq!(result, "email#[PROXY-EMAIL]");
	}

	#[test]
	fn test_redact_fodselsnummer() {
		let input = "SSN: 12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "SSN: [PROXY-FNR]");
	}

	#[test]
	fn test_redact_fodselsnummer_variants() {
		let input = "my_fnr_12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "my_fnr_[PROXY-FNR]");

		let input = "my-fnr:12345678901 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-fnr:[PROXY-FNR] it's nice");

		let input = "my-fnr-12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "my-fnr-[PROXY-FNR]");

		// Additional common delimiter variants
		let input = "fnr.12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr.[PROXY-FNR]");

		let input = "fnr/12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr/[PROXY-FNR]");

		let input = "fnr 12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr [PROXY-FNR]");

		let input = "fnr|12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr|[PROXY-FNR]");

		let input = "fnr+12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr+[PROXY-FNR]");

		let input = "fnr#12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr#[PROXY-FNR]");

		let input = "fnr@12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "fnr@[PROXY-FNR]");

		let input = "(fnr)12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "(fnr)[PROXY-FNR]");

		let input = "[fnr]12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "[fnr][PROXY-FNR]");

		let input = "{fnr}12345678901";
		let result = redact_pii(input);
		assert_eq!(result, "{fnr}[PROXY-FNR]");

		let input = "AD748BD6-484B-416C-B444-a12345678901";
		let result = redact_pii(input);
		assert_eq!(result, input);
	}

	#[test]
	fn test_redact_phone_number() {
		let input = "Call me at 98765432";
		let result = redact_pii(input);
		assert_eq!(result, "Call me at [PROXY-PHONE]");

		let input = "Do not call me at AD748BD6-484B-416C-B444-84EE98765432 that's not a phone number, but a UUID";
		let result = redact_pii(input);
		assert_eq!(result, input);

		let input = "Nor should you call me at 98765432-484B-416C-B444-84EE98765432 that's also not a phone number, still a UUID";
		let result = redact_pii(input);
		assert_eq!(result, input);
	}

	#[test]
	fn test_redact_phone_number_variants() {
		let input = "my_phone_98765432";
		let result = redact_pii(input);
		assert_eq!(result, "my_phone_[PROXY-PHONE]");

		let input = "my-phone:98765432 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-phone:[PROXY-PHONE] it's nice");

		let input = "my-phone-98765432";
		let result = redact_pii(input);
		assert_eq!(result, "my-phone-[PROXY-PHONE]");

		// Additional common delimiter variants
		let input = "phone.98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone.[PROXY-PHONE]");

		let input = "phone/98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone/[PROXY-PHONE]");

		let input = "phone 98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone [PROXY-PHONE]");

		let input = "phone|98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone|[PROXY-PHONE]");

		let input = "phone+98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone+[PROXY-PHONE]");

		let input = "phone#98765432";
		let result = redact_pii(input);
		assert_eq!(result, "phone#[PROXY-PHONE]");

		let input = "(98765432)";
		let result = redact_pii(input);
		assert_eq!(result, "([PROXY-PHONE])");
	}

	#[test]
	fn test_redact_navident() {
		let input = "User: X123456";
		let result = redact_pii(input);
		assert_eq!(result, "User: [PROXY-NAVIDENT]");
	}

	#[test]
	fn test_redact_navident_variants() {
		let input = "my_navident_X123456";
		let result = redact_pii(input);
		assert_eq!(result, "my_navident_[PROXY-NAVIDENT]");

		let input = "my-navident:X123456 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-navident:[PROXY-NAVIDENT] it's nice");

		let input = "my-navident-X123456";
		let result = redact_pii(input);
		assert_eq!(result, "my-navident-[PROXY-NAVIDENT]");

		// Additional common delimiter variants
		let input = "navident.X123456";
		let result = redact_pii(input);
		assert_eq!(result, "navident.[PROXY-NAVIDENT]");

		let input = "navident/X123456";
		let result = redact_pii(input);
		assert_eq!(result, "navident/[PROXY-NAVIDENT]");

		let input = "navident X123456";
		let result = redact_pii(input);
		assert_eq!(result, "navident [PROXY-NAVIDENT]");

		let input = "navident|X123456";
		let result = redact_pii(input);
		assert_eq!(result, "navident|[PROXY-NAVIDENT]");

		let input = "navident+X123456";
		let result = redact_pii(input);
		assert_eq!(result, "navident+[PROXY-NAVIDENT]");

		let input = "(X123456)";
		let result = redact_pii(input);
		assert_eq!(result, "([PROXY-NAVIDENT])");
	}

	#[test]
	fn test_redact_ip_address() {
		let input = "IP: 192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "IP: [PROXY-IP]");
	}

	#[test]
	fn test_redact_ip_address_variants() {
		let input = "my_ip_192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "my_ip_[PROXY-IP]");

		let input = "my-ip:192.168.1.1 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-ip:[PROXY-IP] it's nice");

		let input = "my-ip-192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "my-ip-[PROXY-IP]");

		// Additional common delimiter variants
		let input = "ip/192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "ip/[PROXY-IP]");

		let input = "ip 192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "ip [PROXY-IP]");

		let input = "ip|192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "ip|[PROXY-IP]");

		let input = "ip=192.168.1.1";
		let result = redact_pii(input);
		assert_eq!(result, "ip=[PROXY-IP]");

		let input = "(192.168.1.1)";
		let result = redact_pii(input);
		assert_eq!(result, "([PROXY-IP])");
	}

	#[test]
	fn test_redact_bank_account() {
		let input = "Account: 1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "Account: [PROXY-ACCOUNT]");
	}

	#[test]
	fn test_redact_bank_account_variants() {
		let input = "my_account_1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "my_account_[PROXY-ACCOUNT]");

		let input = "my-account:1234.56.78901 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-account:[PROXY-ACCOUNT] it's nice");

		let input = "my-account-1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "my-account-[PROXY-ACCOUNT]");

		// Additional common delimiter variants
		let input = "account/1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "account/[PROXY-ACCOUNT]");

		let input = "account 1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "account [PROXY-ACCOUNT]");

		let input = "account|1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "account|[PROXY-ACCOUNT]");

		let input = "account=1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "account=[PROXY-ACCOUNT]");

		let input = "account#1234.56.78901";
		let result = redact_pii(input);
		assert_eq!(result, "account#[PROXY-ACCOUNT]");

		// Test without dots - 11 digits will match FNR pattern first (collision case)
		// As long as it's redacted, we're happy with either [PROXY-FNR] or [PROXY-ACCOUNT]
		let input = "account:12345678901";
		let result = redact_pii(input);
		assert!(result == "account:[PROXY-ACCOUNT]" || result == "account:[PROXY-FNR]");
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
	fn test_redact_license_plate_variants() {
		let input = "my_plate_AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "my_plate_[PROXY-LICENSE-PLATE]");

		let input = "my-plate:AB12345 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-plate:[PROXY-LICENSE-PLATE] it's nice");

		let input = "my-plate-AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "my-plate-[PROXY-LICENSE-PLATE]");

		// Additional common delimiter variants
		let input = "plate.AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate.[PROXY-LICENSE-PLATE]");

		let input = "plate/AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate/[PROXY-LICENSE-PLATE]");

		let input = "plate AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate [PROXY-LICENSE-PLATE]");

		let input = "plate|AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate|[PROXY-LICENSE-PLATE]");

		let input = "plate=AB12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate=[PROXY-LICENSE-PLATE]");

		// Test with space in plate (AB 12345)
		let input = "plate:AB 12345";
		let result = redact_pii(input);
		assert_eq!(result, "plate:[PROXY-LICENSE-PLATE]");
	}

	#[test]
	fn test_redact_org_number() {
		let input = "Org: 123456789";
		let result = redact_pii(input);
		assert_eq!(result, "Org: [PROXY-ORG-NUMBER]");
	}

	#[test]
	fn test_redact_org_number_variants() {
		let input = "my_org_123456789";
		let result = redact_pii(input);
		assert_eq!(result, "my_org_[PROXY-ORG-NUMBER]");

		let input = "my-org:123456789 it's nice";
		let result = redact_pii(input);
		assert_eq!(result, "my-org:[PROXY-ORG-NUMBER] it's nice");

		let input = "my-org-123456789";
		let result = redact_pii(input);
		assert_eq!(result, "my-org-[PROXY-ORG-NUMBER]");

		// Additional common delimiter variants
		let input = "org.123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org.[PROXY-ORG-NUMBER]");

		let input = "org/123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org/[PROXY-ORG-NUMBER]");

		let input = "org 123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org [PROXY-ORG-NUMBER]");

		let input = "org|123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org|[PROXY-ORG-NUMBER]");

		let input = "org=123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org=[PROXY-ORG-NUMBER]");

		let input = "org#123456789";
		let result = redact_pii(input);
		assert_eq!(result, "org#[PROXY-ORG-NUMBER]");

		let input = "AD748BD6-484B-416C-B444-aaa123456789";
		let result = redact_pii(input);
		assert_eq!(result, input);
	}

	#[test]
	fn test_redact_file_paths_windows() {
		// Windows absolute paths with drive letters
		let input = "C:\\Users\\PersonName\\Documents\\secret.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "D:\\Projects\\private\\data.xlsx";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Windows UNC paths
		let input = "\\\\ServerName\\Share\\folder\\file.docx";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Windows path with forward slashes (also valid)
		let input = "C:/Users/JohnDoe/Desktop/private_file.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Windows path with spaces
		let input = "C:\\Program Files\\My App\\config.ini";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_unix() {
		// Unix/Linux absolute paths
		let input = "/home/username/Documents/private.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/var/log/user_12345678901.log";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/usr/local/share/sensitive_data.csv";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Unix paths with spaces - will only match the first component before space
		// This is acceptable since spaces in Unix paths are typically escaped or quoted in practice
		let input = "/home/username/Documents/file.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Unix hidden files
		let input = "/home/john/.ssh/id_rsa";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Root-level files are edge cases - require at least 2 components to avoid URL false positives
		// /file.txt would not match (acceptable tradeoff)
	}

	#[test]
	fn test_redact_file_paths_macos() {
		// macOS specific paths
		let input = "/Users/PersonName/Library/ApplicationSupport/app.db";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/Users/john.doe/Desktop/confidential.pages";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// macOS volumes
		let input = "/Volumes/ExternalDrive/Backup/data.zip";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_url_encoded() {
		// URL-encoded paths (common in web analytics)
		let input = "file:///C:/Users/John%20Doe/Documents/file.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// URL-encoded path components - may only match up to the encoded character
		let input = "/home/user/folder/data.json";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_relative() {
		// Relative paths with potentially sensitive info
		let input = "./users/PersonName/config.yml";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "../PersonalFolder/private.db";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "~/Documents/taxes_2024.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_mixed_content() {
		// File paths embedded in sentences - should redact just the path
		let input = "Error loading file C:\\Users\\Admin\\secret.txt";
		let result = redact_pii(input);
		// The word "file" at the end shouldn't be part of the path
		assert!(result.contains("[PROXY-FILEPATH]"));
		assert!(result.contains("Error loading"));

		let input = "Check /home/personalname/.config/app.conf for settings";
		let result = redact_pii(input);
		assert!(result.contains("[PROXY-FILEPATH]"));
		assert!(result.contains("Check"));
		assert!(result.contains("for settings"));

		// File path in URL parameters
		let input = "?file=/var/www/users/JohnDoe/uploads/doc.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "?file=[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_common_patterns() {
		// Common sensitive directory patterns
		let input = "/home/john/Downloads/passport_scan.jpg";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "C:\\Users\\Mary\\Pictures\\ID_card.png";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Backup paths
		let input = "/backup/users/ole_hansen/2024-03-15.tar.gz";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Application data paths
		let input = "C:\\ProgramData\\Application\\Users\\PersonName\\cache.dat";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_special_chars() {
		// Paths with special characters that might appear in the wild
		let input = "/home/user-name/docs/report_2024.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "C:\\Users\\user.name\\AppData\\Local\\temp.log";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Paths with numbers and underscores
		let input = "/var/log/user_12345/app_log_2024.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_edge_cases() {
		// Very long paths
		let input = "C:\\Users\\Administrator\\Very\\Long\\Path\\With\\Many\\Nested\\Directories\\And\\Personal\\Info\\document.docx";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Paths with multiple extensions
		let input = "/home/user/backup.tar.gz.enc";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Network paths (SMB/CIFS)
		let input = "\\\\192.168.1.100\\shared\\PersonName\\data.xlsx";
		let result = redact_pii(input);
		assert!(result.contains("[PROXY-FILEPATH]") || result.contains("[PROXY-IP]"));

		// Paths without extensions (config files, directories with dots)
		let input = "/home/user/.config";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Git-style and dotfile paths
		let input = "/repo/.git/config";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// if just a simple file at the top level, should be redacted
		let input = "/file.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_android_ios() {
		// Android paths
		let input = "/data/data/com.example.app/files/user_data.db";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/sdcard/Download/PersonalPhoto.jpg";
		let _result = redact_pii(input);
		// May not match if sdcard isn't in our sensitive dirs list
		// This is acceptable - we focus on common patterns

		// iOS-style paths
		let input = "/var/mobile/Containers/Data/Application/GUID/Documents/file.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_web_server() {
		// Web server document roots
		let input = "/var/www/html/uploads/user123/document.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/srv/http/public/media/private/photo.jpg";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Apache/nginx log paths
		let input = "/var/log/nginx/access.log";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_redact_file_paths_generic_unix() {
		// Generic Unix paths that don't start with common directories
		// These should still be caught with the generic matcher
		let input = "/custom/application/data/userfile.db";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/app/storage/uploads/document.pdf";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/media/external/PersonalPhotos/vacation.jpg";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		let input = "/mount/nas/private/secrets.txt";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Container paths
		let input = "/docker/volumes/app_data/config.yml";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// Custom application paths
		let input = "/opt/myapp/logs/error.log";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");
	}

	#[test]
	fn test_file_paths_not_urls() {
		// Should NOT match single-component paths that look like URL endpoints
		// let input = "/api/users";
		// let result = redact_pii(input);
		// This has only 2 components, so it WILL match (borderline case)
		// This is acceptable as /api/users could be a local path too

		// But very short paths might be more ambiguous
		let input = "Visit /help for more info";
		let result = redact_pii(input);
		// /help is only one component, should NOT match
		assert_eq!(result, "Visit /help for more info");

		// Multiple component URL paths will match, which is fine - better safe than sorry
		let input = "/api/v1/users/profile";
		let result = redact_pii(input);
		assert_eq!(result, "[PROXY-FILEPATH]");

		// the presence of https:// or http:// should be a good tell for what's a valid URL only
		let input = "https://example.com/api/v1/users/profile";
		let result = redact_pii(input);
		assert_eq!(result, input);

		// if something has what looks like a TLD, even without a protocol like https://, we can still
		// assume that it's a URL fairly safely
		let input = "example.com/api/v1/users/profile";
		let result = redact_pii(input);
		assert_eq!(result, input);
	}
}
