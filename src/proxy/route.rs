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
		Route::Other(path)
	}
}
