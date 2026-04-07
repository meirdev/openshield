use std::net::IpAddr;

use maxminddb::{Reader, geoip2};

#[derive(Clone)]
pub struct GeoIpLookup {
    pub as_num: Option<u32>,
    pub as_org: Option<String>,
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

pub struct GeoIp {
    city_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn open(
        city_path: impl AsRef<std::path::Path>,
        asn_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, maxminddb::MaxMindDbError> {
        let city_reader = Reader::open_readfile(city_path)?;
        let asn_reader = Reader::open_readfile(asn_path)?;

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoIpLookup {
        let mut result = GeoIpLookup {
            as_num: None,
            as_org: None,
            city: None,
            continent: None,
            country: None,
            lat: None,
            lon: None,
            metro_code: None,
            postal_code: None,
            region: None,
            region_code: None,
            timezone: None,
        };

        if let Ok(lookup) = self.asn_reader.lookup(ip) {
            if let Ok(Some(asn)) = lookup.decode::<geoip2::Asn>() {
                result.as_num = asn.autonomous_system_number;
                result.as_org = asn.autonomous_system_organization.map(String::from);
            }
        }

        if let Ok(lookup) = self.city_reader.lookup(ip) {
            if let Ok(Some(city)) = lookup.decode::<geoip2::City>() {
                result.city = city.city.names.english.map(String::from);
                result.continent = city.continent.code.map(String::from);
                result.country = city.country.iso_code.map(String::from);
                result.lat = city.location.latitude;
                result.lon = city.location.longitude;
                result.metro_code = city.location.metro_code;
                result.timezone = city.location.time_zone.map(String::from);
                result.postal_code = city.postal.code.map(String::from);

                if let Some(first) = city.subdivisions.first() {
                    result.region = first.names.english.map(String::from);
                    result.region_code = first.iso_code.map(String::from);
                }
            }
        }

        result
    }
}
