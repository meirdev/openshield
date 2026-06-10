use serde_json::{Map, Value};
use wirefilter_engine::{ExecutionContext, Field, FilterAst, Scheme, Visitor};

struct FieldCollector {
    fields: Vec<String>,
}

impl<'a> Visitor<'a> for FieldCollector {
    fn visit_field(&mut self, f: &'a Field) {
        let name = f.name();
        if !self.fields.iter().any(|x| x == name) {
            self.fields.push(name.to_string());
        }
    }
}

pub fn referenced_fields(ast: &FilterAst) -> Vec<String> {
    let mut collector = FieldCollector { fields: Vec::new() };
    ast.walk(&mut collector);
    collector.fields
}

pub fn capture_into(
    scheme: &Scheme,
    ctx: &ExecutionContext<'_>,
    field_names: &[String],
    out: &mut Map<String, Value>,
) {
    for name in field_names {
        let Ok(field) = scheme.get_field(name) else {
            continue;
        };
        let Some(value) = ctx.get_field_value(field) else {
            continue;
        };
        if let Ok(json) = serde_json::to_value(value) {
            out.insert(name.clone(), json);
        }
    }
}
