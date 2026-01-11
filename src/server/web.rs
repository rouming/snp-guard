use axum::{
    extract::{Extension, Path, Multipart},
    response::{Html, IntoResponse, Redirect},
    body::Body,
};
use tokio_util::io::ReaderStream;
use askama::Template;
use std::path::PathBuf;
use std::fs;
use std::process::Command;
use common::snpguard::AttestationRecord;
use std::sync::Arc;
use crate::service_core::{self, ServiceState};

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate { vms: Vec<AttestationRecord> }

#[derive(Template)]
#[template(path = "create.html")]
struct CreateTemplate {}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditTemplate { vm: AttestationRecord }

pub async fn index(Extension(state): Extension<Arc<ServiceState>>) -> impl IntoResponse {
    match service_core::list_records_core(&state).await {
        Ok(vms) => {
            let template = IndexTemplate { vms };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Template error: {}", e)).into_response(),
            }
        },
        Err(e) => Html(format!("Failed to load records: {}", e)).into_response(),
    }
}

pub async fn create_form() -> impl IntoResponse {
    let template = CreateTemplate {};
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Template error: {}", e)).into_response(),
    }
}

pub async fn create_action(
    Extension(state): Extension<Arc<ServiceState>>,
    mut multipart: Multipart
) -> impl IntoResponse {
    let mut os_name = String::new();
    let mut secret = String::new();
    let mut vcpus: u32 = 1;
    let mut vcpu_type = String::new();
    let mut kernel_params = String::new();
    let mut service_url = String::new();
    let mut allowed_debug = false;
    let mut allowed_migrate_ma = false;
    let mut allowed_smt = true; // Default to true
    let mut min_tcb_bootloader = 0u32;
    let mut min_tcb_tee = 0u32;
    let mut min_tcb_snp = 0u32;
    let mut min_tcb_microcode = 0u32;
    let mut id_key: Option<Vec<u8>> = None;
    let mut auth_key: Option<Vec<u8>> = None;
    let mut firmware: Option<Vec<u8>> = None;
    let mut kernel: Option<Vec<u8>> = None;
    let mut initrd: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        if let Some(_) = field.file_name() {
             let data = field.bytes().await.unwrap();
             if data.is_empty() { continue; }

             // Enforce file size limits
             let max_size = match name.as_str() {
                "firmware" => 10 * 1024 * 1024, // 10 MB
                "kernel" => 50 * 1024 * 1024,  // 50 MB
                "initrd" => 50 * 1024 * 1024,  // 50 MB
                "id_key" | "auth_key" => 10 * 1024, // 10 KB for keys
                _ => continue,
             };

             if data.len() > max_size {
                 return Html(format!("<h1>File Too Large</h1><p>File '{}' exceeds maximum size of {} bytes</p>", name, max_size)).into_response();
             }

            match name.as_str() {
                "id_key" => id_key = Some(data.to_vec()),
                "auth_key" => auth_key = Some(data.to_vec()),
                "firmware" => firmware = Some(data.to_vec()),
                "kernel" => kernel = Some(data.to_vec()),
                "initrd" => initrd = Some(data.to_vec()),
                _ => {}
            }
        } else {
            let txt = field.text().await.unwrap();
            match name.as_str() {
                "os_name" => os_name = txt,
                "secret" => secret = txt,
                "vcpus" => vcpus = txt.parse().unwrap_or(1),
                "vcpu_type" => vcpu_type = txt,
                "kernel_params" => kernel_params = txt,
                "service_url" => service_url = txt,
                "allowed_debug" => allowed_debug = txt == "true",
                "allowed_migrate_ma" => allowed_migrate_ma = txt == "true",
                "allowed_smt" => allowed_smt = txt == "true",
                "min_tcb_bootloader" => min_tcb_bootloader = txt.parse().unwrap_or(0),
                "min_tcb_tee" => min_tcb_tee = txt.parse().unwrap_or(0),
                "min_tcb_snp" => min_tcb_snp = txt.parse().unwrap_or(0),
                "min_tcb_microcode" => min_tcb_microcode = txt.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    // Validate required fields
    if os_name.is_empty() || secret.is_empty() || service_url.is_empty() ||
       id_key.is_none() || auth_key.is_none() || firmware.is_none() ||
       kernel.is_none() || initrd.is_none() {
        return Html("<h1>Error</h1><p>All fields are required</p>").into_response();
    }

    let req = common::snpguard::CreateRecordRequest {
        os_name,
        id_key: id_key.unwrap(),
        auth_key: auth_key.unwrap(),
        firmware: firmware.unwrap(),
        kernel: kernel.unwrap(),
        initrd: initrd.unwrap(),
        kernel_params,
        vcpus,
        vcpu_type,
        service_url,
        secret,
        allowed_debug,
        allowed_migrate_ma,
        allowed_smt,
        min_tcb_bootloader,
        min_tcb_tee,
        min_tcb_snp,
        min_tcb_microcode,
    };
    match service_core::create_record_core(&state, req).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!("<h1>Error Creating Record</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn view_record(Extension(state): Extension<Arc<ServiceState>>, Path(id): Path<String>) -> impl IntoResponse {
    match service_core::get_record_core(&state, id).await {
        Ok(Some(vm)) => {
            let template = EditTemplate { vm };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Template error: {}", e)).into_response(),
            }
        },
        Ok(None) => Html("<h1>Not Found</h1><p>Record not found</p>").into_response(),
        Err(e) => Html(format!("<h1>Error</h1><p>Failed to load record: {}</p>", e)).into_response(),
    }
}

pub async fn update_action(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Get current record first to populate defaults
    let current_record = match service_core::get_record_core(&state, id.clone()).await {
        Ok(Some(record)) => record,
        Ok(None) => return Html("<h1>Not Found</h1><p>Record not found</p>").into_response(),
        Err(e) => return Html(format!("<h1>Error</h1><p>Failed to load record: {}</p>", e)).into_response(),
    };

    let mut os_name = Some(current_record.os_name);
    let mut secret = Some(current_record.secret);
    let mut enabled = Some(true); // Default to enabled unless explicitly disabled
    let mut vcpus = Some(4u32);
    let mut vcpu_type = Some(current_record.vcpu_type);
    let mut kernel_params = Some(current_record.kernel_params.clone());
    let mut service_url = None;
    let mut allowed_debug = Some(current_record.allowed_debug);
    let mut allowed_migrate_ma = Some(current_record.allowed_migrate_ma);
    let mut allowed_smt = Some(current_record.allowed_smt);
    let mut min_tcb_bootloader = Some(current_record.min_tcb_bootloader as u32);
    let mut min_tcb_tee = Some(current_record.min_tcb_tee as u32);
    let mut min_tcb_snp = Some(current_record.min_tcb_snp as u32);
    let mut min_tcb_microcode = Some(current_record.min_tcb_microcode as u32);
    let mut id_key: Option<Vec<u8>> = None;
    let mut auth_key: Option<Vec<u8>> = None;
    let mut firmware: Option<Vec<u8>> = None;
    let mut kernel: Option<Vec<u8>> = None;
    let mut initrd: Option<Vec<u8>> = None;

    // Extract existing service URL from kernel params
    if let Some(params) = &kernel_params {
        if let Some(url_part) = params.split("rd.attest.url=").nth(1) {
            service_url = Some(url_part.split_whitespace().next().unwrap_or("").to_string());
        }
    }

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        if let Some(_) = field.file_name() {
            let data = field.bytes().await.unwrap();
            if data.is_empty() { continue; }

            // Enforce file size limits
            let max_size = match name.as_str() {
                "firmware" => 10 * 1024 * 1024, // 10 MB
                "kernel" => 50 * 1024 * 1024,  // 50 MB
                "initrd" => 50 * 1024 * 1024,  // 50 MB
                "id_key" | "auth_key" => 10 * 1024, // 10 KB for keys
                _ => continue,
            };

            if data.len() > max_size {
                return Html(format!("<h1>File Too Large</h1><p>File '{}' exceeds maximum size of {} bytes</p>", name, max_size)).into_response();
            }

            match name.as_str() {
                "id_key" => id_key = Some(data.to_vec()),
                "auth_key" => auth_key = Some(data.to_vec()),
                "firmware" => firmware = Some(data.to_vec()),
                "kernel" => kernel = Some(data.to_vec()),
                "initrd" => initrd = Some(data.to_vec()),
                _ => {}
            }
        } else {
            let txt = field.text().await.unwrap();
            match name.as_str() {
                "os_name" => os_name = Some(txt),
                "secret" => secret = Some(txt),
                "enabled" => enabled = Some(true),
                "vcpus" => vcpus = Some(txt.parse().unwrap_or(4)),
                "vcpu_type" => vcpu_type = Some(txt),
                "kernel_params" => kernel_params = Some(txt),
                "service_url" => service_url = Some(txt),
                "allowed_debug" => allowed_debug = Some(txt == "true"),
                "allowed_migrate_ma" => allowed_migrate_ma = Some(txt == "true"),
                "allowed_smt" => allowed_smt = Some(txt == "true"),
                "min_tcb_bootloader" => min_tcb_bootloader = Some(txt.parse().unwrap_or(0)),
                "min_tcb_tee" => min_tcb_tee = Some(txt.parse().unwrap_or(0)),
                "min_tcb_snp" => min_tcb_snp = Some(txt.parse().unwrap_or(0)),
                "min_tcb_microcode" => min_tcb_microcode = Some(txt.parse().unwrap_or(0)),
                _ => {}
            }
        }
    }

    let req = common::snpguard::UpdateRecordRequest {
        id: id.clone(),
        os_name,
        id_key,
        auth_key,
        firmware,
        kernel,
        initrd,
        kernel_params,
        vcpus,
        vcpu_type,
        service_url,
        secret,
        enabled,
        allowed_debug,
        allowed_migrate_ma,
        allowed_smt,
        min_tcb_bootloader,
        min_tcb_tee,
        min_tcb_snp,
        min_tcb_microcode,
    };
    match service_core::update_record_core(&state, req).await {
        Ok(_) => Redirect::to(&format!("/view/{}", id)).into_response(),
        Err(e) => Html(format!("<h1>Error Updating Record</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn toggle_enabled(Extension(state): Extension<Arc<ServiceState>>, Path(id): Path<String>) -> impl IntoResponse {
    let req = common::snpguard::ToggleEnabledRequest { id: id.clone() };
    match service_core::toggle_enabled_core(&state, req, true).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!("<h1>Error</h1><p>Failed to toggle enabled status: {}</p>", e)).into_response(),
    }
}

pub async fn delete_action(Extension(state): Extension<Arc<ServiceState>>, Path(id): Path<String>) -> impl IntoResponse {
    match service_core::delete_record_core(&state, id).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!("<h1>Error Deleting Record</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn download_artifact(Path((id, file_name)): Path<(String, String)>) -> impl IntoResponse {
    if file_name.contains("..") { return "Invalid path".into_response(); }
    let artifact_dir = PathBuf::from("artifacts").join(&id);
    let path = artifact_dir.join(&file_name);

    // SquashFS Generator
    if file_name == "artifacts.squashfs" {
        let def_path = artifact_dir.join("squash.def");
        // Strict permissions
        fs::write(&def_path, "/ d 755 0 0\nfirmware-code.fd m 444 0 0\nvmlinuz m 444 0 0\ninitrd.img m 444 0 0\nkernel-params.txt m 444 0 0\nid-block.bin m 444 0 0\nid-auth.bin m 444 0 0\n").unwrap();
        Command::new("mksquashfs")
            .arg(&artifact_dir).arg(&path)
            .arg("-noappend").arg("-all-root").arg("-pf").arg(&def_path)
            .status().unwrap();
    }
    
    // Tarball Generator - create with correct filenames in root (/)
    if file_name == "artifacts.tar.gz" {
        // Create tarball with files at root level
        let status = Command::new("tar")
            .arg("-czf").arg(&path)
            .arg("-C").arg(&artifact_dir)
            .arg("--transform=s|^|/|")
            .arg("firmware-code.fd")
            .arg("vmlinuz")
            .arg("initrd.img")
            .arg("kernel-params.txt")
            .arg("id-block.bin")
            .arg("id-auth.bin")
            .status();
        
        if status.is_err() {
            return "Failed to create tarball".into_response();
        }
    }

    match tokio::fs::File::open(path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            let content_disposition = format!("attachment; filename=\"{}\"", file_name);
            use axum::http::HeaderMap;
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
            headers.insert("Content-Disposition", content_disposition.parse().unwrap());
            (headers, body).into_response()
        },
        Err(_) => "File not found".into_response()
    }
}
