use crate::config::Hook;
use crate::errors::Error;
use handlebars::Handlebars;
use serde::Serialize;
use std::fs::File;
use std::io::prelude::*;
use std::process::{Command, Stdio};

macro_rules! get_hook_output {
    ($out: expr, $reg: ident, $data: expr) => {{
        match $out {
            Some(path) => {
                let path = $reg.render_template(path, $data)?;
                let file = File::create(path)?;
                Stdio::from(file)
            }
            None => Stdio::null(),
        }
    }};
}

pub fn call_multiple<T: Serialize>(data: &T, hooks: &Vec<Hook>) -> Result<(), Error> {
    for hook in hooks.iter() {
        call(data, &hook)?;
    }
    Ok(())
}

pub fn call<T: Serialize>(data: &T, hook: &Hook) -> Result<(), Error> {
    let reg = Handlebars::new();
    let mut v = vec![];
    let args = match &hook.args {
        Some(lst) => {
            for fmt in lst.iter() {
                let s = reg.render_template(fmt, data)?;
                v.push(s);
            }
            v.as_slice()
        }
        None => &[],
    };
    let mut cmd = Command::new(&hook.cmd)
        .args(args)
        .stdout(get_hook_output!(&hook.stdout, reg, data))
        .stderr(get_hook_output!(&hook.stderr, reg, data))
        .stdin(match &hook.stdin {
            Some(_) => Stdio::piped(),
            None => Stdio::null(),
        })
        .spawn()?;
    if hook.stdin.is_some() {
        let data_in = reg.render_template(&hook.stdin.to_owned().unwrap(), data)?;
        let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
        stdin.write_all(data_in.as_bytes())?;
    }
    Ok(())
}
