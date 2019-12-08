use digest::{Digest, DynDigest};
use md5::Md5;
use regex::{Captures, Regex};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Result, Write};
use std::mem::MaybeUninit;
use std::process::{Command, Stdio};
use structopt::StructOpt;
use tempfile::{NamedTempFile, TempPath};

const EXTRACT_PKGBUILD_SCRIPT: &[u8] = include_bytes!("extract_pkgbuild.sh");

#[derive(Debug, structopt::StructOpt)]
#[structopt(about)]
struct Opt {
    new_version: String,
}

#[derive(Debug)]
struct Pkgbuild {
    content: String,
    regex: Regex,
}

impl Pkgbuild {
    fn new() -> Result<Pkgbuild> {
        Ok(Pkgbuild {
            content: std::fs::read_to_string("PKGBUILD")?,
            regex: Regex::new(r"(.+)=(\([^\)]+\)|.+)").unwrap(),
        })
    }

    fn set(&mut self, k: &str, v: &str) {
        match self.regex.replace_all(&self.content, |caps: &Captures| {
            format!("{}={}", &caps[1], if &caps[1] == k { v } else { &caps[2] })
        }) {
            Cow::Borrowed(_) => (),
            Cow::Owned(o) => self.content = o,
        }
    }
}

impl AsRef<[u8]> for Pkgbuild {
    fn as_ref(&self) -> &[u8] {
        self.content.as_bytes()
    }
}

#[derive(Debug, Deserialize)]
struct Source {
    filename: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    sources: Vec<Source>,
    hashes: Vec<String>,
}

impl Metadata {
    fn digests(&self) -> Vec<Box<dyn DynDigest>> {
        let mut digests = Vec::<Box<dyn DynDigest>>::with_capacity(self.hashes.len());
        for hash in &self.hashes {
            digests.push(match hash.as_str() {
                "md5" => Box::new(Md5::new()),
                "sha1" => Box::new(Sha1::new()),
                "sha224" => Box::new(Sha224::new()),
                "sha256" => Box::new(Sha256::new()),
                "sha384" => Box::new(Sha384::new()),
                "sha512" => Box::new(Sha512::new()),
                _ => panic!("Unsupported hash {}", hash),
            });
        }
        digests
    }
}

#[derive(Debug)]
struct ExtractPkgbuild {
    script: TempPath,
}

impl ExtractPkgbuild {
    fn new() -> Result<ExtractPkgbuild> {
        let script = NamedTempFile::new()?;
        let (mut file, path) = script.into_parts();
        file.write_all(EXTRACT_PKGBUILD_SCRIPT)?;
        Ok(ExtractPkgbuild { script: path })
    }

    fn run<T: AsRef<[u8]>>(&self, input: T) -> Result<Metadata> {
        let input = input.as_ref();
        let mut child = Command::new("bash")
            .arg(&self.script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(input)?;
        }
        let output = child.wait_with_output()?;
        Ok(serde_json::from_slice(&output.stdout).unwrap())
    }
}

fn run(opt: Opt) -> Result<()> {
    let mut pkgbuild = Pkgbuild::new()?;
    pkgbuild.set("pkgver", &opt.new_version);
    let metadata = ExtractPkgbuild::new()?.run(&pkgbuild)?;
    let mut digests = metadata.digests();
    let mut digest_hashes: Vec<Vec<String>> = vec![Vec::new(); digests.len()];
    for source in &metadata.sources {
        println!("{} -> {}", source.url, source.filename);
        let mut response = reqwest::get(&source.url)
            .unwrap()
            .error_for_status()
            .unwrap();

        let mut file = File::create(&source.filename)?;
        let mut buf = MaybeUninit::<[u8; 8 * 1024]>::uninit();
        loop {
            let len = match response.read(unsafe {
                std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8 * 1024)
            }) {
                Ok(0) => break,
                Ok(len) => len,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let buf_read = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
            file.write_all(&buf_read)?;
            for digest in &mut digests {
                digest.input(&buf_read);
            }
        }

        for (digest, hashes) in digests.iter_mut().zip(digest_hashes.iter_mut()) {
            hashes.push(hex::encode(digest.result_reset()));
        }
    }
    for (hash_name, hashes) in metadata.hashes.iter().zip(digest_hashes) {
        let hashsum = format!("{}sums", hash_name);
        pkgbuild.set(
            &hashsum,
            &format!(
                "('{}')",
                hashes.join(&format!("'\n{}  '", " ".repeat(hashsum.len())))
            ),
        );
    }
    println!("{}", pkgbuild.content);

    // TODO:
    // - Generate .SRCINFO
    // - Create git commit
    // - Write altered PKGBUILD
    // - Run namcap?
    // - Build package?
    Ok(())
}

fn main() {
    if let Err(e) = run(Opt::from_args()) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
