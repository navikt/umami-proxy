use std::fmt::{self, Display, Formatter};

use strum::{EnumString, IntoStaticStr};

#[derive(Debug, EnumString, IntoStaticStr)]
pub enum AmplitrudeProxyError {
	RequestContainsInvalidJson,
	JsonCoParseError,
	NoMatchingPeer,
}

impl Display for AmplitrudeProxyError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}
#[derive(Debug, IntoStaticStr)]
pub enum ErrorDescription {
	SslError,
	ConnectionError,
	UpstreamConnectionFailure,
	UntrackedError,
	AmplitrudeProxyError(AmplitrudeProxyError),
}
impl ErrorDescription {
	pub fn as_str(&self) -> &str {
		match self {
			Self::AmplitrudeProxyError(e) => e.into(),
			_ => self.into(),
		}
	}
}
impl Display for ErrorDescription {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl From<AmplitrudeProxyError> for ErrorDescription {
	fn from(error: AmplitrudeProxyError) -> ErrorDescription {
		Self::AmplitrudeProxyError(error)
	}
}
