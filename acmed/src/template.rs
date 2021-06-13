use acme_common::error::Error;
use serde::Serialize;
use serde_json::Value;
use tinytemplate::TinyTemplate;

macro_rules! default_format {
    ($value: ident, $output: ident) => {{
        $output.push_str(&$value.to_string());
        Ok(())
    }};
}

fn formatter_rev_labels(value: &Value, output: &mut String) -> tinytemplate::error::Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(v) => default_format!(v, output),
        Value::Number(v) => default_format!(v, output),
        Value::String(v) => {
            let s = v.rsplit('.').collect::<Vec<&str>>().join(".");
            output.push_str(&s);
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn render_template<T>(template: &str, data: &T) -> Result<String, Error>
where
    T: Serialize,
{
    let mut reg = TinyTemplate::new();
    reg.add_formatter("rev_labels", formatter_rev_labels);
    reg.add_template("reg", template)?;
    Ok(reg.render("reg", data)?)
}

#[cfg(test)]
mod tests {
    use super::render_template;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TplTest {
        foo: String,
        bar: u64,
    }

    #[test]
    fn test_basic_template() {
        let c = TplTest {
            foo: String::from("test"),
            bar: 42,
        };
        let tpl = "This is { foo } { bar -} !";
        let rendered = render_template(tpl, &c);
        assert!(rendered.is_ok());
        let rendered = rendered.unwrap();
        assert_eq!(rendered, "This is test 42!");
    }

    #[test]
    fn test_formatter_rev_labels() {
        let c = TplTest {
            foo: String::from("mx1.example.org"),
            bar: 42,
        };
        let tpl = "{ foo } - { foo | rev_labels }";
        let rendered = render_template(tpl, &c);
        assert!(rendered.is_ok());
        let rendered = rendered.unwrap();
        assert_eq!(rendered, "mx1.example.org - org.example.mx1");
    }
}
