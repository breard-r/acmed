pub use crate::config::HookType;
use crate::logs::HasLogger;
use crate::template::render_template;
use acme_common::error::Error;
use async_process::{Command, Stdio};
use futures::AsyncWriteExt;
use serde::Serialize;
use std::collections::hash_map::Iter;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
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
	pub identifiers: Vec<String>,
	pub key_type: String,
	pub status: String,
	pub is_success: bool,
	pub env: HashMap<String, String>,
}

imple_hook_data_env!(PostOperationHookData);

#[derive(Clone, Serialize)]
pub struct ChallengeHookData {
	pub identifier: String,
	pub identifier_tls_alpn: String,
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
	pub hook_type: HashSet<HookType>,
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
	($logger: expr, $out: expr, $data: expr, $hook_name: expr, $out_name: expr) => {{
		match $out {
			Some(path) => {
				let path = render_template(path, $data)?;
				$logger.trace(&format!("hook \"{}\": {}: {path}", $hook_name, $out_name));
				let file = File::create(&path)?;
				Stdio::from(file)
			}
			None => Stdio::null(),
		}
	}};
}

async fn call_single<L, T>(logger: &L, data: &T, hook: &Hook) -> Result<(), Error>
where
	L: HasLogger,
	T: Clone + HookEnvData + Serialize,
{
	logger.debug(&format!("calling hook \"{}\"", hook.name));
	let mut v = vec![];
	let args = match &hook.args {
		Some(lst) => {
			for fmt in lst.iter() {
				let s = render_template(fmt, &data)?;
				v.push(s);
			}
			v.as_slice()
		}
		None => &[],
	};
	logger.trace(&format!("hook \"{}\": cmd: {}", hook.name, hook.cmd));
	logger.trace(&format!("hook \"{}\": args: {args:?}", hook.name));
	let mut cmd = Command::new(&hook.cmd)
		.envs(data.get_env())
		.args(args)
		.stdout(get_hook_output!(
			logger,
			&hook.stdout,
			&data,
			&hook.name,
			"stdout"
		))
		.stderr(get_hook_output!(
			logger,
			&hook.stderr,
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
			let data_in = render_template(s, &data)?;
			logger.trace(&format!("hook \"{}\": string stdin: {data_in}", hook.name));
			let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
			stdin.write_all(data_in.as_bytes()).await?;
		}
		HookStdin::File(f) => {
			let file_name = render_template(f, &data)?;
			logger.trace(&format!("hook \"{}\": file stdin: {file_name}", hook.name));
			let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
			let file = File::open(&file_name).map_err(|e| Error::from(e).prefix(&file_name))?;
			let buf_reader = BufReader::new(file);
			for line in buf_reader.lines() {
				let line = format!("{}\n", line?);
				stdin.write_all(line.as_bytes()).await?;
			}
		}
		HookStdin::None => {}
	}
	// TODO: add a timeout
	let status = cmd.status().await?;
	if !status.success() && !hook.allow_failure {
		let msg = match status.code() {
			Some(code) => format!("unrecoverable failure: code {code}").into(),
			None => "unrecoverable failure".into(),
		};
		return Err(msg);
	}
	match status.code() {
		Some(code) => logger.debug(&format!("hook \"{}\": exited: code {code}", hook.name)),
		None => logger.debug(&format!("hook \"{}\": exited", hook.name)),
	};
	Ok(())
}

pub async fn call<L, T>(
	logger: &L,
	hooks: &[Hook],
	data: &T,
	hook_type: HookType,
) -> Result<(), Error>
where
	L: HasLogger,
	T: Clone + HookEnvData + Serialize,
{
	for hook in hooks.iter().filter(|h| h.hook_type.contains(&hook_type)) {
		call_single(logger, data, hook)
			.await
			.map_err(|e| e.prefix(&hook.name))?;
	}
	Ok(())
}
