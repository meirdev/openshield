use wirefilter_engine::{Scheme, SchemeBuilder, Type};

use super::functions;
use super::lists::{BytesListDefinition, IpListDefinition};

macro_rules! opt {
    ($b:expr, $name:expr, Str) => {
        $b.add_optional_field($name, Type::Bytes).unwrap()
    };
    ($b:expr, $name:expr, Int) => {
        $b.add_optional_field($name, Type::Int).unwrap()
    };
    ($b:expr, $name:expr, Bool) => {
        $b.add_optional_field($name, Type::Bool).unwrap()
    };
    ($b:expr, $name:expr, Ip) => {
        $b.add_optional_field($name, Type::Ip).unwrap()
    };
    ($b:expr, $name:expr, Arr<Str>) => {
        $b.add_optional_field($name, Type::Array(Type::Bytes.into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Arr<Arr<Str>>) => {
        $b.add_optional_field($name, Type::Array(Type::Array(Type::Bytes.into()).into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Map<Arr<Str>>) => {
        $b.add_optional_field($name, Type::Map(Type::Array(Type::Bytes.into()).into()))
            .unwrap()
    };
}

pub fn build(score_names: &[String]) -> Scheme {
    let mut b = SchemeBuilder::new();

    // fields
    opt!(b, "ip.src", Ip);
    opt!(b, "ip.src.asnum", Int);
    opt!(b, "ip.src.city", Str);
    opt!(b, "ip.src.continent", Str);
    opt!(b, "ip.src.country", Str);
    opt!(b, "ip.src.lat", Str);
    opt!(b, "ip.src.lon", Str);
    opt!(b, "ip.src.metro_code", Str);
    opt!(b, "ip.src.postal_code", Str);
    opt!(b, "ip.src.region", Str);
    opt!(b, "ip.src.region_code", Str);
    opt!(b, "ip.src.timezone.name", Str);

    opt!(b, "http.cookie", Str);
    opt!(b, "http.host", Str);
    opt!(b, "http.referer", Str);
    opt!(b, "http.user_agent", Str);
    opt!(b, "http.x_forwarded_for", Str);
    opt!(b, "http.request.method", Str);
    opt!(b, "http.request.version", Str);
    opt!(b, "http.request.full_uri", Str);
    opt!(b, "http.request.uri", Str);
    opt!(b, "http.request.uri.path", Str);
    opt!(b, "http.request.uri.path.extension", Str);
    opt!(b, "http.request.uri.query", Str);
    opt!(b, "http.request.timestamp.sec", Int);
    opt!(b, "http.request.timestamp.msec", Int);

    opt!(b, "http.request.headers", Map<Arr<Str>>);
    opt!(b, "http.request.headers.names", Arr<Str>);
    opt!(b, "http.request.headers.values", Arr<Str>);
    opt!(b, "http.request.cookies", Map<Arr<Str>>);
    opt!(b, "http.request.cookies.names", Arr<Str>);
    opt!(b, "http.request.cookies.values", Arr<Str>);
    opt!(b, "http.request.uri.args", Map<Arr<Str>>);
    opt!(b, "http.request.uri.args.names", Arr<Str>);
    opt!(b, "http.request.uri.args.values", Arr<Str>);
    opt!(b, "http.request.accepted_languages", Arr<Str>);

    opt!(b, "http.request.body.raw", Str);
    opt!(b, "http.request.body.size", Int);
    opt!(b, "http.request.body.truncated", Bool);
    opt!(b, "http.request.body.mime", Str);
    opt!(b, "http.request.body.form", Map<Arr<Str>>);
    opt!(b, "http.request.body.form.names", Arr<Str>);
    opt!(b, "http.request.body.form.values", Arr<Str>);
    opt!(b, "http.request.body.multipart", Map<Arr<Str>>);
    opt!(b, "http.request.body.multipart.values", Arr<Str>);
    opt!(b, "http.request.body.multipart.names", Arr<Arr<Str>>);
    opt!(
        b,
        "http.request.body.multipart.content_types",
        Arr<Arr<Str>>
    );
    opt!(
        b,
        "http.request.body.multipart.content_dispositions",
        Arr<Arr<Str>>
    );
    opt!(
        b,
        "http.request.body.multipart.content_transfer_encodings",
        Arr<Arr<Str>>
    );
    opt!(b, "http.request.body.multipart.filenames", Arr<Arr<Str>>);

    opt!(b, "http.response.code", Int);
    opt!(b, "http.response.content_type.media_type", Str);
    opt!(b, "http.response.headers", Map<Arr<Str>>);
    opt!(b, "http.response.headers.names", Arr<Str>);
    opt!(b, "http.response.headers.values", Arr<Str>);

    opt!(b, "http.response.body.raw", Str);
    opt!(b, "http.response.body.size", Int);
    opt!(b, "http.response.body.truncated", Bool);

    opt!(b, "ssl", Bool);

    for name in score_names {
        opt!(b, &format!("oss.waf.score.{name}"), Int);
    }

    // functions
    functions::register_all(&mut b);

    // lists
    b.add_list(Type::Ip, IpListDefinition).unwrap();
    b.add_list(Type::Bytes, BytesListDefinition).unwrap();

    b.build()
}
