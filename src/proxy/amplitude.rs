use amplitude::Event;
use bytes::Bytes;
use serde_json::Value;

// use crate::proxy::redact::redact_json;

use super::redact;

/// This function, among other things, handles the bytes deserialization and serialization of the http request body
pub(crate) fn process_amplitude_event(body: &Vec<u8>) -> Option<Bytes> {
	let mut json: serde_json::Value = match serde_json::de::from_slice(body) {
		Err(e) => {
			eprintln!("JSON not well-formed: {e}");
			return None;
		},
		Ok(j) => j,
	};
	dbg!(&json);

	//	let processed_body = redact::process_event(&mut json);

	//	dbg!(&processed_body);
	// Some(Bytes::copy_from_slice(
	// 	serde_json::to_string(&processed_body)
	// 		.expect("Unable to serialize JSON into string")
	// 		.as_bytes(),
	// ))
	None
}

#[cfg(test)]
mod tests {
	use super::*;
}
