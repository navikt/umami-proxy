use fancy_regex::Regex;
use once_cell::sync::Lazy;

/// Privacy check patterns for detecting potentially sensitive data
/// These patterns are used to scan analytics data for Norwegian personal information
pub static PRIVACY_PATTERNS: Lazy<Vec<PrivacyPattern>> = Lazy::new(|| {
	vec![
		// Norwegian National ID Number (11 digits)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			name: "Fødselsnummer",
			redaction_label: "PROXY-FNR",
			regex: Regex::new(r"(?<!\d)\d{11}(?!\d)").unwrap(),
		},
		// NAV identifier (letter followed by 6 digits)
		// Use negative lookaround for alphanumeric to avoid matching partial IDs
		PrivacyPattern {
			name: "Navident",
			redaction_label: "PROXY-NAVIDENT",
			regex: Regex::new(r"(?<![a-zA-Z0-9])[a-zA-Z]\d{6}(?!\d)").unwrap(),
		},
		// Email address
		// Simple practical regex that matches 99% of real emails in use today
		// Underscore is a valid email character, so "my_email@example.com" is treated as one email
		PrivacyPattern {
			name: "E-post",
			redaction_label: "PROXY-EMAIL",
			regex: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
		},
		// IP address
		// Use negative lookaround for digits and dots to avoid matching partial IPs
		PrivacyPattern {
			name: "IP-adresse",
			redaction_label: "PROXY-IP",
			regex: Regex::new(r"(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)").unwrap(),
		},
		// Phone number (8 digits starting with 2-9)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			name: "Telefonnummer",
			redaction_label: "PROXY-PHONE",
			regex: Regex::new(r"(?<!\d)[2-9]\d{7}(?!\d)").unwrap(),
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
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			name: "Kontonummer",
			redaction_label: "PROXY-ACCOUNT",
			regex: Regex::new(r"(?<!\d)\d{4}\.?\d{2}\.?\d{5}(?!\d)").unwrap(),
		},
		// Organization number (9 digits)
		// Use negative lookaround for digits to avoid matching partial numbers
		PrivacyPattern {
			name: "Organisasjonsnummer",
			redaction_label: "PROXY-ORG-NUMBER",
			regex: Regex::new(r"(?<!\d)\d{9}(?!\d)").unwrap(),
		},
		// License plate (2 letters followed by 5 digits)
		// Use negative lookaround for alphanumeric to avoid matching partial plates
		PrivacyPattern {
			name: "Bilnummer",
			redaction_label: "PROXY-LICENSE-PLATE",
			regex: Regex::new(r"(?<![a-zA-Z])[A-Z]{2}\s?\d{5}(?!\d)").unwrap(),
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
	}

	#[test]
	fn test_redact_phone_number() {
		let input = "Call me at 98765432";
		let result = redact_pii(input);
		assert_eq!(result, "Call me at [PROXY-PHONE]");
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
	}
}
