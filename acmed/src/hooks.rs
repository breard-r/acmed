use crate::certificate::Certificate;
pub use crate::config::HookType;
use acme_common::error::Error;
use handlebars::Handlebars;
use serde::Serialize;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, fmt};

pub trait HookEnvData {
    fn set_env(&mut self, env: &HashMap<String, String>);
    fn get_env(&self) -> Iter<String, String>;
}

fn deref<F, G>(t: (&F, &G)) -> (F, G)
where
    F: Clone,
    G: Clone,
{
    ((*(t.0)).to_owned(), (*(t.1)).to_owned())
}

macro_rules! imple_hook_data_env {
    ($t: ty) => {
        impl HookEnvData for $t {
            fn set_env(&mut self, env: &HashMap<String, String>) {
                for (key, value) in env::vars().chain(env.iter().map(deref)) {
                    self.env.insert(key, value);
                }
            }

            fn get_env(&self) -> Iter<String, String> {
                self.env.iter()
            }
        }
    };
}

#[derive(Clone, Serialize)]
pub struct PostOperationHookData {
    pub domains: Vec<String>,
    pub algorithm: String,
    pub status: String,
    pub is_success: bool,
    pub env: HashMap<String, String>,
}

imple_hook_data_env!(PostOperationHookData);

#[derive(Clone, Serialize)]
pub struct ChallengeHookData {
    pub domain: String,
    pub challenge: String,
    pub file_name: String,
    pub proof: String,
    pub is_clean_hook: bool,
    pub env: HashMap<String, String>,
}

imple_hook_data_env!(ChallengeHookData);

#[derive(Clone, Serialize)]
pub struct FileStorageHookData {
    // TODO: add the current operation (create/edit)
    pub file_name: String,
    pub file_directory: String,
    pub file_path: PathBuf,
    pub env: HashMap<String, String>,
}

imple_hook_data_env!(FileStorageHookData);

#[derive(Clone, Debug)]
pub enum HookStdin {
    File(String),
    Str(String),
    None,
}

#[derive(Clone, Debug)]
pub struct Hook {
    pub name: String,
    pub hook_type: Vec<HookType>,
    pub cmd: String,
    pub args: Option<Vec<String>>,
    pub stdin: HookStdin,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub allow_failure: bool,
}

impl fmt::Display for Hook {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

macro_rules! get_hook_output {
    ($cert: expr, $out: expr, $reg: ident, $data: expr, $hook_name: expr, $out_name: expr) => {{
        match $out {
            Some(path) => {
                let path = $reg.render_template(path, $data)?;
                $cert.trace(&format!("Hook {}: {}: {}", $hook_name, $out_name, &path));
                let file = File::create(&path)?;
                Stdio::from(file)
            }
            None => Stdio::null(),
        }
    }};
}

fn call_single<T>(cert: &Certificate, data: &T, hook: &Hook) -> Result<(), Error>
where
    T: Clone + HookEnvData + Serialize,
{
    cert.debug(&format!("Calling hook: {}", hook.name));
    let reg = Handlebars::new();
    let mut v = vec![];
    let args = match &hook.args {
        Some(lst) => {
            for fmt in lst.iter() {
                let s = reg.render_template(fmt, &data)?;
                v.push(s);
            }
            v.as_slice()
        }
        None => &[],
    };
    cert.trace(&format!("Hook {}: cmd: {}", hook.name, hook.cmd));
    cert.trace(&format!("Hook {}: args: {:?}", hook.name, args));
    let mut cmd = Command::new(&hook.cmd)
        .envs(data.get_env())
        .args(args)
        .stdout(get_hook_output!(
            cert,
            &hook.stdout,
            reg,
            &data,
            &hook.name,
            "stdout"
        ))
        .stderr(get_hook_output!(
            cert,
            &hook.stderr,
            reg,
            &data,
            &hook.name,
            "stderr"
        ))
        .stdin(match &hook.stdin {
            HookStdin::Str(_) | HookStdin::File(_) => Stdio::piped(),
            HookStdin::None => Stdio::null(),
        })
        .spawn()?;
    match &hook.stdin {
        HookStdin::Str(s) => {
            let data_in = reg.render_template(&s, &data)?;
            cert.trace(&format!("Hook {}: string stdin: {}", hook.name, &data_in));
            let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
            stdin.write_all(data_in.as_bytes())?;
        }
        HookStdin::File(f) => {
            let file_name = reg.render_template(&f, &data)?;
            cert.trace(&format!("Hook {}: file stdin: {}", hook.name, &file_name));
            let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
            let file = File::open(&file_name)?;
            let buf_reader = BufReader::new(file);
            for line in buf_reader.lines() {
                let line = format!("{}\n", line?);
                stdin.write_all(line.as_bytes())?;
            }
        }
        HookStdin::None => {}
    }
    // TODO: add a timeout
    let status = cmd.wait()?;
    if !status.success() && !hook.allow_failure {
        let msg = match status.code() {
            Some(code) => format!("Unrecoverable failure: code {}", code).into(),
            None => "Unrecoverable failure".into(),
        };
        return Err(msg);
    }
    match status.code() {
        Some(code) => cert.debug(&format!("Hook {}: exited: code {}", hook.name, code)),
        None => cert.debug(&format!("Hook {}: exited", hook.name)),
    };
    Ok(())
}

pub fn call<T>(cert: &Certificate, data: &T, hook_type: HookType) -> Result<(), Error>
where
    T: Clone + HookEnvData + Serialize,
{
    for hook in cert
        .hooks
        .iter()
        .filter(|h| h.hook_type.contains(&hook_type))
    {
        call_single(cert, data, &hook).map_err(|e| e.prefix(&hook.name))?;
    }
    Ok(())
}
