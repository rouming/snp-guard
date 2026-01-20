use regex::Regex;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

/// Represents a GRUB menu entry
#[derive(Debug)]
pub struct GrubEntry {
    pub kernel: String,
    pub initrd: Option<String>,
    pub params: String,
    pub is_default: bool,
}

/// Parse a grub.cfg file into a vector of GrubEntry
pub fn parse_grub_cfg<P: AsRef<Path>>(path: P) -> io::Result<Vec<GrubEntry>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut entries = Vec::new();
    let mut in_menuentry = false;
    let mut kernel = String::new();
    let mut initrd = None;
    let mut params = String::new();
    let mut continuation = String::new();

    let mut default_index: Option<usize> = None;
    let mut menu_counter: usize = 0;

    // Regex to strip $VAR or ${VAR}
    let var_re = Regex::new(r"\$\{?[a-zA-Z0-9_]+\}?").unwrap();

    for line in reader.lines() {
        let mut line = line?;
        line = line.trim().to_string();

        // skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // check for default index
        if line.starts_with("set default=") {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    if let Ok(idx) = line[start + 1..start + 1 + end].parse::<usize>() {
                        default_index = Some(idx);
                    }
                }
            }
            continue;
        }

        // handle line continuation \
        if line.ends_with('\\') {
            continuation.push_str(&line[..line.len() - 1]);
            continuation.push(' ');
            continue;
        }
        if !continuation.is_empty() {
            continuation.push_str(&line);
            line = continuation.clone();
            continuation.clear();
        }

        // start of menuentry
        if line.starts_with("menuentry ") {
            in_menuentry = true;
            kernel.clear();
            initrd = None;
            params.clear();
            continue;
        }

        if in_menuentry {
            if line.starts_with('}') {
                // end of menuentry
                if !kernel.is_empty() {
                    entries.push(GrubEntry {
                        kernel: kernel.clone(),
                        initrd: initrd.clone(),
                        params: params.clone(),
                        is_default: default_index == Some(menu_counter),
                    });
                }
                in_menuentry = false;
                menu_counter += 1;
                continue;
            }

            // linux lines
            if line.starts_with("linux")
                || line.starts_with("linux16")
                || line.starts_with("linuxefi")
            {
                let mut parts = line.split_whitespace();
                let _linux_cmd = parts.next(); // discard 'linux*'
                if let Some(k) = parts.next() {
                    kernel = k.to_string();
                }
                let raw_params = parts.collect::<Vec<_>>().join(" ");
                params = var_re.replace_all(&raw_params, "").to_string();
                params = params.trim().to_string(); // collapse extra spaces
            }

            // initrd lines
            if line.starts_with("initrd")
                || line.starts_with("initrd16")
                || line.starts_with("initrdefi")
            {
                let mut parts = line.split_whitespace();
                let _initrd_cmd = parts.next();
                if let Some(i) = parts.next() {
                    initrd = Some(i.to_string());
                }
            }
        }
    }

    Ok(entries)
}
