use acme_common::error::Error;
use minijinja::{value::Value, Environment};
use serde::Serialize;

fn formatter_rev_labels(value: Value) -> Result<Value, minijinja::Error> {
	if let Some(value) = value.as_str() {
		Ok(value.rsplit('.').collect::<Vec<&str>>().join(".").into())
	} else {
		Ok(value)
	}
}

pub fn render_template<T>(template: &str, data: &T) -> Result<String, Error>
where
	T: Serialize,
{
	let mut environment = Environment::new();
	environment.add_filter("rev_labels", formatter_rev_labels);
	environment.add_template("template", template)?;
	let template = environment.get_template("template")?;
	Ok(template.render(data)?)
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
		let tpl = "This is {{ foo }} {{ bar -}} !";
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
		let tpl = "{{ foo }} - {{ foo | rev_labels }}";
		let rendered = render_template(tpl, &c);
		assert!(rendered.is_ok());
		let rendered = rendered.unwrap();
		assert_eq!(rendered, "mx1.example.org - org.example.mx1");
	}
}
