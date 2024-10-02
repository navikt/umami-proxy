// This is the appinfo struct as per the ingress-collector app
#[derive(Clone, Debug)]
pub struct AppInfo {
	pub app: String,
	pub namespace: String,
	pub ingress: String,
	pub creation_timestamp: String,
}

// This is the appinfo as per I just want a working cache
#[derive(Clone, Debug)]
pub struct IppAnfo {
	pub app: String,
}
