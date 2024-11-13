use crate::hooks::{self, FileStorageHookData, Hook, HookEnvData, HookType};
use crate::logs::HasLogger;
use crate::template::render_template;
use acme_common::b64_encode;
use acme_common::crypto::{KeyPair, X509Certificate};
use acme_common::error::Error;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
pub struct FileManager {
	pub account_name: String,
	pub account_directory: String,
	pub crt_name: String,
	pub crt_name_format: String,
	pub crt_directory: String,
	pub crt_key_type: String,
	pub cert_file_mode: u32,
	pub cert_file_owner: Option<String>,
	pub cert_file_group: Option<String>,
	pub cert_file_ext: Option<String>,
	pub pk_file_mode: u32,
	pub pk_file_owner: Option<String>,
	pub pk_file_group: Option<String>,
	pub pk_file_ext: Option<String>,
	pub hooks: Vec<Hook>,
	pub env: HashMap<String, String>,
}

impl HasLogger for FileManager {
	fn warn(&self, msg: &str) {
		log::warn!("{self}: {msg}");
	}

	fn info(&self, msg: &str) {
		log::info!("{self}: {msg}");
	}

	fn debug(&self, msg: &str) {
		log::debug!("{self}: {msg}");
	}

	fn trace(&self, msg: &str) {
		log::trace!("{self}: {msg}");
	}
}

impl fmt::Display for FileManager {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let s = if !self.crt_name.is_empty() {
			format!("certificate \"{}_{}\"", self.crt_name, self.crt_key_type)
		} else {
			format!("account \"{}\"", self.account_name)
		};
		write!(f, "{s}")
	}
}

#[derive(Clone)]
enum FileType {
	Account,
	PrivateKey,
	Certificate,
}

impl fmt::Display for FileType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let s = match self {
			FileType::Account => "account",
			FileType::PrivateKey => "pk",
			FileType::Certificate => "crt",
		};
		write!(f, "{s}")
	}
}

#[derive(Clone, Serialize)]
pub struct CertFileFormat {
	pub ext: String,
	pub file_type: String,
	pub key_type: String,
	pub name: String,
}

fn get_file_full_path(
	fm: &FileManager,
	file_type: FileType,
) -> Result<(String, String, PathBuf), Error> {
	let base_path = match file_type {
		FileType::Account => &fm.account_directory,
		FileType::PrivateKey => &fm.crt_directory,
		FileType::Certificate => &fm.crt_directory,
	};
	let ext = match file_type {
		FileType::Account => "bin".to_string(),
		FileType::PrivateKey => fm.pk_file_ext.clone().unwrap_or("pem".to_string()),
		FileType::Certificate => fm.cert_file_ext.clone().unwrap_or("pem".to_string()),
	};
	let file_name = match file_type {
		FileType::Account => format!(
			"{account}.{file_type}.{ext}",
			account = b64_encode(&fm.account_name),
			file_type = file_type,
			ext = ext
		),
		FileType::PrivateKey | FileType::Certificate => {
			let fmt_data = CertFileFormat {
				key_type: fm.crt_key_type.to_string(),
				ext,
				file_type: file_type.to_string(),
				name: fm.crt_name.to_owned(),
			};
			render_template(&fm.crt_name_format, &fmt_data)?
		}
	};
	let mut path = PathBuf::from(&base_path);
	path.push(&file_name);
	Ok((base_path.to_string(), file_name, path))
}

fn get_file_path(fm: &FileManager, file_type: FileType) -> Result<PathBuf, Error> {
	let (_, _, path) = get_file_full_path(fm, file_type)?;
	Ok(path)
}

async fn read_file(fm: &FileManager, path: &Path) -> Result<Vec<u8>, Error> {
	fm.trace(&format!("reading file {path:?}"));
	let mut file = File::open(path)
		.await
		.map_err(|e| Error::from(e).prefix(&path.display().to_string()))?;
	let mut contents = vec![];
	file.read_to_end(&mut contents).await?;
	Ok(contents)
}

#[cfg(unix)]
fn set_owner(fm: &FileManager, path: &Path, file_type: FileType) -> Result<(), Error> {
	let (uid, gid) = match file_type {
		FileType::Certificate => (fm.cert_file_owner.to_owned(), fm.cert_file_group.to_owned()),
		FileType::PrivateKey => (fm.pk_file_owner.to_owned(), fm.pk_file_group.to_owned()),
		FileType::Account => {
			// The account file does not need to be accessible to users other different from the current one.
			return Ok(());
		}
	};
	let uid = match uid {
		Some(u) => {
			if u.bytes().all(|b| b.is_ascii_digit()) {
				let raw_uid = u
					.parse::<u32>()
					.map_err(|_| Error::from("unable to parse the UID"))?;
				let nix_uid = nix::unistd::Uid::from_raw(raw_uid);
				Some(nix_uid)
			} else {
				let user = nix::unistd::User::from_name(&u)?;
				user.map(|u| u.uid)
			}
		}
		None => None,
	};
	let gid = match gid {
		Some(g) => {
			if g.bytes().all(|b| b.is_ascii_digit()) {
				let raw_gid = g
					.parse::<u32>()
					.map_err(|_| Error::from("unable to parse the GID"))?;
				let nix_gid = nix::unistd::Gid::from_raw(raw_gid);
				Some(nix_gid)
			} else {
				let grp = nix::unistd::Group::from_name(&g)?;
				grp.map(|g| g.gid)
			}
		}
		None => None,
	};
	match uid {
		Some(u) => fm.trace(&format!("{path:?}: setting the uid to {}", u.as_raw())),
		None => fm.trace(&format!("{path:?}: uid unchanged")),
	};
	match gid {
		Some(g) => fm.trace(&format!("{path:?}: setting the gid to {}", g.as_raw())),
		None => fm.trace(&format!("{path:?}: gid unchanged")),
	};
	match nix::unistd::chown(path, uid, gid) {
		Ok(_) => Ok(()),
		Err(e) => Err(format!("{e}").into()),
	}
}

async fn write_file(fm: &FileManager, file_type: FileType, data: &[u8]) -> Result<(), Error> {
	let (file_directory, file_name, path) = get_file_full_path(fm, file_type.clone())?;
	let mut hook_data = FileStorageHookData {
		file_name,
		file_directory,
		file_path: path.to_owned(),
		env: HashMap::new(),
	};
	hook_data.set_env(&fm.env);
	let is_new = !path.is_file();

	if is_new {
		hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePreCreate).await?;
	} else {
		hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePreEdit).await?;
	}

	fm.trace(&format!("writing file {path:?}"));
	let mut file = if cfg!(unix) {
		let mut options = OpenOptions::new();
		options.mode(match &file_type {
			FileType::Certificate => fm.cert_file_mode,
			FileType::PrivateKey => fm.pk_file_mode,
			FileType::Account => crate::DEFAULT_ACCOUNT_FILE_MODE,
		});
		options
			.write(true)
			.create(true)
			.open(&path)
			.await
			.map_err(|e| Error::from(e).prefix(&path.display().to_string()))?
	} else {
		File::create(&path)
			.await
			.map_err(|e| Error::from(e).prefix(&path.display().to_string()))?
	};
	file.write_all(data)
		.await
		.map_err(|e| Error::from(e).prefix(&path.display().to_string()))?;
	if cfg!(unix) {
		set_owner(fm, &path, file_type).map_err(|e| e.prefix(&path.display().to_string()))?;
	}

	if is_new {
		hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePostCreate).await?;
	} else {
		hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePostEdit).await?;
	}
	Ok(())
}

pub async fn get_account_data(fm: &FileManager) -> Result<Vec<u8>, Error> {
	let path = get_file_path(fm, FileType::Account)?;
	read_file(fm, &path).await
}

pub async fn set_account_data(fm: &FileManager, data: &[u8]) -> Result<(), Error> {
	write_file(fm, FileType::Account, data).await
}

pub async fn get_keypair_path(fm: &FileManager) -> Result<PathBuf, Error> {
	get_file_path(fm, FileType::PrivateKey)
}

pub async fn get_keypair(fm: &FileManager) -> Result<KeyPair, Error> {
	let path = get_keypair_path(fm).await?;
	let raw_key = read_file(fm, &path).await?;
	let key = KeyPair::from_pem(&raw_key)?;
	Ok(key)
}

pub async fn set_keypair(fm: &FileManager, key_pair: &KeyPair) -> Result<(), Error> {
	let data = key_pair.private_key_to_pem()?;
	write_file(fm, FileType::PrivateKey, &data).await
}

pub async fn get_certificate_path(fm: &FileManager) -> Result<PathBuf, Error> {
	get_file_path(fm, FileType::Certificate)
}

pub async fn get_certificate(fm: &FileManager) -> Result<X509Certificate, Error> {
	let path = get_certificate_path(fm).await?;
	let raw_crt = read_file(fm, &path).await?;
	let crt = X509Certificate::from_pem(&raw_crt)?;
	Ok(crt)
}

pub async fn write_certificate(fm: &FileManager, data: &[u8]) -> Result<(), Error> {
	write_file(fm, FileType::Certificate, data).await
}

fn check_files(fm: &FileManager, file_types: &[FileType]) -> bool {
	for t in file_types.iter().cloned() {
		let path = match get_file_path(fm, t) {
			Ok(p) => p,
			Err(_) => {
				return false;
			}
		};
		fm.trace(&format!(
			"testing file path: {}",
			path.to_str().unwrap_or_default()
		));
		if !path.is_file() {
			return false;
		}
	}
	true
}

pub fn account_files_exists(fm: &FileManager) -> bool {
	let file_types = vec![FileType::Account];
	check_files(fm, &file_types)
}

pub fn certificate_files_exists(fm: &FileManager) -> bool {
	let file_types = vec![FileType::PrivateKey, FileType::Certificate];
	check_files(fm, &file_types)
}
