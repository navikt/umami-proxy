#[derive(Debug, PartialEq)]
pub enum Route {
	Umami(String),
	Amplitude(String),
	Other(String), //Someone did a goof
}

pub fn match_route(path: String) -> Route {
	if path.starts_with("/umami") {
		Route::Umami(path.to_string())
	} else if path.starts_with("/collect") {
		Route::Amplitude(path.to_string())
	} else {
		Route::Amplitude(path)
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn show_starts_with() {
		assert_eq!(
			"/collect".starts_with("/collect"),
			"/collect-auto".starts_with("/collect")
		);
	}
}
