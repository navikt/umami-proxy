use amplitude::Event;
use bytes::Bytes;

/// This function does all the manipulation/treatment of the HTTP request body received from some browser's amplitude sdk
/// 1. Parse bytes as some version of an Amplitude event
/// 1. Replace (coarsen) downstream IP w/(coarse) geo data
/// 1. Set `ProxyVersion` to name of this app (so we @ NAV can identify where the Amplitude event came from over @ Amplitude)
/// 1. Use the `crate::proxy::redact` module's logic to redact any data inside `(event|user)_properties` of the event body
pub(crate) fn process_amplitude_event(body: &Vec<u8>) -> Option<Bytes> {
	let json: serde_json::Value = match serde_json::de::from_slice(body) {
		Err(e) => {
			eprintln!("JSON not well-formed: {e}");
			return None;
		},
		Ok(j) => j,
	};
	let event = match Event::from_json(json) {
		Err(e) => {
			eprintln!("Amplitude event not well-formed: {e}");
			return None;
		},
		Ok(e) => e,
	};
	dbg!(&event);
	todo!()
}
