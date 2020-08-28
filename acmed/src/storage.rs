use crate::hooks::{self, FileStorageHookData, Hook, HookEnvData, HookType};
use crate::logs::HasLogger;
use acme_common::b64_encode;
use acme_common::crypto::{KeyPair, X509Certificate};
use acme_common::error::Error;
use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;

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
    pub pk_file_mode: u32,
    pub pk_file_owner: Option<String>,
    pub pk_file_group: Option<String>,
    pub hooks: Vec<Hook>,
    pub env: HashMap<String, String>,
}

impl HasLogger for FileManager {
    fn warn(&self, msg: &str) {
        log::warn!("{}: {}", &self.crt_name, msg);
    }

    fn info(&self, msg: &str) {
        log::info!("{}: {}", &self.crt_name, msg);
    }

    fn debug(&self, msg: &str) {
        log::debug!("{}: {}", &self.crt_name, msg);
    }

    fn trace(&self, msg: &str) {
        log::trace!("{}: {}", &self.crt_name, msg);
    }
}

#[derive(Clone)]
enum FileType {
    AccountPrivateKey,
    AccountPublicKey,
    PrivateKey,
    Certificate,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            FileType::AccountPrivateKey => "priv-key",
            FileType::AccountPublicKey => "pub-key",
            FileType::PrivateKey => "pk",
            FileType::Certificate => "crt",
        };
        write!(f, "{}", s)
    }
}

fn get_file_full_path(
    fm: &FileManager,
    file_type: FileType,
) -> Result<(String, String, PathBuf), Error> {
    let base_path = match file_type {
        FileType::AccountPrivateKey | FileType::AccountPublicKey => &fm.account_directory,
        FileType::PrivateKey => &fm.crt_directory,
        FileType::Certificate => &fm.crt_directory,
    };
    let file_name = match file_type {
        FileType::AccountPrivateKey | FileType::AccountPublicKey => format!(
            "{account}.{file_type}.{ext}",
            account = b64_encode(&fm.account_name),
            file_type = file_type.to_string(),
            ext = "pem"
        ),
        FileType::PrivateKey | FileType::Certificate => {
            // TODO: use fm.crt_name_format instead of a string literal
            format!(
                "{name}_{algo}.{file_type}.{ext}",
                name = fm.crt_name,
                algo = fm.crt_key_type,
                file_type = file_type.to_string(),
                ext = "pem"
            )
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

fn read_file(fm: &FileManager, path: &PathBuf) -> Result<Vec<u8>, Error> {
    fm.trace(&format!("Reading file {:?}", path));
    let mut file = File::open(path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

#[cfg(unix)]
fn set_owner(fm: &FileManager, path: &PathBuf, file_type: FileType) -> Result<(), Error> {
    let (uid, gid) = match file_type {
        FileType::Certificate => (fm.cert_file_owner.to_owned(), fm.cert_file_group.to_owned()),
        FileType::PrivateKey => (fm.pk_file_owner.to_owned(), fm.pk_file_group.to_owned()),
        FileType::AccountPrivateKey | FileType::AccountPublicKey => {
            // The account file does not need to be accessible to users other different from the current one.
            return Ok(());
        }
    };
    let uid = match uid {
        Some(u) => {
            if u.bytes().all(|b| b.is_ascii_digit()) {
                let raw_uid = u
                    .parse::<u32>()
                    .map_err(|_| Error::from("Unable to parse the UID"))?;
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
                    .map_err(|_| Error::from("Unable to parse the GID"))?;
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
        Some(u) => fm.trace(&format!("{:?}: setting the uid to {}", path, u.as_raw())),
        None => fm.trace(&format!("{:?}: uid unchanged", path)),
    };
    match gid {
        Some(g) => fm.trace(&format!("{:?}: setting the gid to {}", path, g.as_raw())),
        None => fm.trace(&format!("{:?}: gid unchanged", path)),
    };
    match nix::unistd::chown(path, uid, gid) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{}", e).into()),
    }
}

fn write_file(fm: &FileManager, file_type: FileType, data: &[u8]) -> Result<(), Error> {
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
        hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePreCreate)?;
    } else {
        hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePreEdit)?;
    }

    fm.trace(&format!("Writing file {:?}", path));
    let mut file = if cfg!(unix) {
        let mut options = OpenOptions::new();
        options.mode(match &file_type {
            FileType::Certificate => fm.cert_file_mode,
            FileType::PrivateKey => fm.pk_file_mode,
            FileType::AccountPublicKey => crate::DEFAULT_ACCOUNT_FILE_MODE,
            FileType::AccountPrivateKey => crate::DEFAULT_ACCOUNT_FILE_MODE,
        });
        options.write(true).create(true).open(&path)?
    } else {
        File::create(&path)?
    };
    file.write_all(data)?;
    if cfg!(unix) {
        set_owner(fm, &path, file_type)?;
    }

    if is_new {
        hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePostCreate)?;
    } else {
        hooks::call(fm, &fm.hooks, &hook_data, HookType::FilePostEdit)?;
    }
    Ok(())
}

pub fn get_account_keypair(fm: &FileManager) -> Result<KeyPair, Error> {
    let path = get_file_path(fm, FileType::AccountPrivateKey)?;
    let raw_key = read_file(fm, &path)?;
    let key = KeyPair::from_pem(&raw_key)?;
    Ok(key)
}

pub fn set_account_keypair(fm: &FileManager, key_pair: &KeyPair) -> Result<(), Error> {
    let pem_pub_key = key_pair.private_key_to_pem()?;
    let pem_priv_key = key_pair.public_key_to_pem()?;
    write_file(fm, FileType::AccountPublicKey, &pem_priv_key)?;
    write_file(fm, FileType::AccountPrivateKey, &pem_pub_key)?;
    Ok(())
}

pub fn get_keypair(fm: &FileManager) -> Result<KeyPair, Error> {
    let path = get_file_path(fm, FileType::PrivateKey)?;
    let raw_key = read_file(fm, &path)?;
    let key = KeyPair::from_pem(&raw_key)?;
    Ok(key)
}

pub fn set_keypair(fm: &FileManager, key_pair: &KeyPair) -> Result<(), Error> {
    let data = key_pair.private_key_to_pem()?;
    write_file(fm, FileType::PrivateKey, &data)
}

pub fn get_certificate(fm: &FileManager) -> Result<X509Certificate, Error> {
    let path = get_file_path(fm, FileType::Certificate)?;
    let raw_crt = read_file(fm, &path)?;
    let crt = X509Certificate::from_pem(&raw_crt)?;
    Ok(crt)
}

pub fn write_certificate(fm: &FileManager, data: &[u8]) -> Result<(), Error> {
    write_file(fm, FileType::Certificate, data)
}

fn check_files(fm: &FileManager, file_types: &[FileType]) -> bool {
    for t in file_types.to_vec() {
        let path = match get_file_path(fm, t) {
            Ok(p) => p,
            Err(_) => {
                return false;
            }
        };
        fm.trace(&format!(
            "Testing file path: {}",
            path.to_str().unwrap_or_default()
        ));
        if !path.is_file() {
            return false;
        }
    }
    true
}

pub fn account_files_exists(fm: &FileManager) -> bool {
    let file_types = vec![FileType::AccountPrivateKey, FileType::AccountPublicKey];
    check_files(fm, &file_types)
}

pub fn certificate_files_exists(fm: &FileManager) -> bool {
    let file_types = vec![FileType::PrivateKey, FileType::Certificate];
    check_files(fm, &file_types)
}
