use acme_common::error::Error;
use serde::Serialize;
use tinytemplate::TinyTemplate;

pub fn render_template<T>(template: &str, data: &T) -> Result<String, Error>
where
    T: Serialize,
{
    let mut reg = TinyTemplate::new();
    reg.add_template("reg", template)?;
    Ok(reg.render("reg", data)?)
}
