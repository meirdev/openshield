use std::net::IpAddr;

pub struct RequestData {
    pub client_ip: Option<IpAddr>,
    pub is_tls: bool,
    pub method: String,
    pub version: String,
    pub host: String,
    pub full_uri: String,
    pub uri: String,
    pub path: String,
    pub query: String,
    pub extension: String,
    pub headers: Vec<(String, String)>,
    pub geo: Option<GeoData>,
}

pub struct GeoData {
    pub asn: Option<u32>,
    pub city: Option<String>,
    pub continent: Option<String>,
    pub country: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub metro_code: Option<u16>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub region_code: Option<String>,
    pub timezone: Option<String>,
}

pub struct ResponseData {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub struct MultipartPartData {
    pub name: Option<String>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub content_transfer_encoding: Option<String>,
    pub value: String,
}
