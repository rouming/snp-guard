use axum::{
    extract::{Extension, Path, Multipart},
    response::{Html, IntoResponse, Redirect},
    Form,
    body::Body,
};
use tokio_util::io::ReaderStream;
use sea_orm::{DatabaseConnection, EntityTrait, QueryOrder, ActiveModelTrait, Set};
use askama::Template;
use entity::vm;
use serde::Deserialize;
use uuid::Uuid;
use std::path::PathBuf;
use std::fs;
use std::process::Command;
use crate::snpguest_wrapper;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate { vms: Vec<vm::Model> }

#[derive(Template)]
#[template(path = "create.html")]
struct CreateTemplate {}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditTemplate { vm: vm::Model }

pub async fn index(Extension(db): Extension<DatabaseConnection>) -> impl IntoResponse {
    let vms = vm::Entity::find().order_by_asc(vm::Column::OsName).all(&db).await.unwrap_or_default();
    Html(IndexTemplate { vms }.render().unwrap())
}

pub async fn create_form() -> impl IntoResponse { Html(CreateTemplate {}.render().unwrap()) }

pub async fn create_action(Extension(db): Extension<DatabaseConnection>, mut multipart: Multipart) -> impl IntoResponse {
    let new_id = Uuid::new_v4().to_string();
    let artifact_dir = PathBuf::from("artifacts").join(&new_id);
    fs::create_dir_all(&artifact_dir).unwrap();

    #[derive(Default)]
    struct FormData {
        os_name: String, secret: String, vcpus: u32, vcpu_type: String,
        kernel_params: String, service_url: String,
    }
    let mut fd = FormData::default();

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
             
             let target = match name.as_str() {
                "id_key" => "id-block-key.pem",
                "auth_key" => "id-auth-key.pem",
                "firmware" => "firmware-code.fd",
                "kernel" => "vmlinuz",
                "initrd" => "initrd.img",
                _ => continue,
             };
             fs::write(artifact_dir.join(target), data).unwrap();
        } else {
            let txt = field.text().await.unwrap();
            match name.as_str() {
                "os_name" => fd.os_name = txt,
                "secret" => fd.secret = txt,
                "vcpus" => fd.vcpus = txt.parse().unwrap_or(1),
                "vcpu_type" => fd.vcpu_type = txt,
                "kernel_params" => fd.kernel_params = txt,
                "service_url" => fd.service_url = txt,
                _ => {}
            }
        }
    }

    let full_params = format!("{} rd.attest.url={}", fd.kernel_params, fd.service_url);
    fs::write(artifact_dir.join("kernel-params.txt"), &full_params).unwrap();

    // Generate Measurements
    if let Err(e) = snpguest_wrapper::generate_measurement_and_block(
        &artifact_dir.join("firmware-code.fd"),
        &artifact_dir.join("vmlinuz"),
        &artifact_dir.join("initrd.img"),
        &full_params,
        fd.vcpus,
        &fd.vcpu_type,
        &artifact_dir.join("id-block-key.pem"),
        &artifact_dir.join("id-auth-key.pem"),
        &artifact_dir,
    ) {
        return Html(format!("<h1>Error Generating Measurement</h1><p>{}</p>", e)).into_response();
    }

    // Get Digests
    let id_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-block-key.pem")).unwrap();
    let auth_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-auth-key.pem")).unwrap();

    // Save DB
    let new_vm = vm::ActiveModel {
        id: Set(new_id),
        os_name: Set(fd.os_name),
        secret: Set(fd.secret),
        vcpu_type: Set(fd.vcpu_type),
        id_key_digest: Set(id_digest),
        auth_key_digest: Set(auth_digest),
        created_at: Set(chrono::Utc::now().naive_utc()),
        enabled: Set(true),
        kernel_params: Set(full_params),
        request_count: Set(0),
        firmware_path: Set("firmware-code.fd".into()),
        kernel_path: Set("vmlinuz".into()),
        initrd_path: Set("initrd.img".into()),
    };
    new_vm.insert(&db).await.unwrap();
    Redirect::to("/").into_response()
}

pub async fn view_record(Path(id): Path<String>, Extension(db): Extension<DatabaseConnection>) -> impl IntoResponse {
    let vm = vm::Entity::find_by_id(id).one(&db).await.unwrap().unwrap();
    Html(EditTemplate { vm }.render().unwrap())
}

pub async fn update_action(
    Path(id): Path<String>,
    Extension(db): Extension<DatabaseConnection>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let vm = vm::Entity::find_by_id(id).one(&db).await.unwrap().unwrap();
    let artifact_dir = PathBuf::from("artifacts").join(&id);
    
    let mut os_name = vm.os_name.clone();
    let mut secret = vm.secret.clone();
    let mut enabled = vm.enabled;
    let mut vcpus = 4u32;
    let mut vcpu_type = vm.vcpu_type.clone();
    let mut kernel_params = vm.kernel_params.clone();
    let mut service_url = String::new();
    let mut files_updated = false;
    
    // Extract service URL from kernel params
    if let Some(url_part) = kernel_params.split("rd.attest.url=").nth(1) {
        service_url = url_part.split_whitespace().next().unwrap_or("").to_string();
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
            
            files_updated = true;
            let target = match name.as_str() {
                "id_key" => "id-block-key.pem",
                "auth_key" => "id-auth-key.pem",
                "firmware" => "firmware-code.fd",
                "kernel" => "vmlinuz",
                "initrd" => "initrd.img",
                _ => continue,
            };
            fs::write(artifact_dir.join(target), data).unwrap();
        } else {
            let txt = field.text().await.unwrap();
            match name.as_str() {
                "os_name" => os_name = txt,
                "secret" => secret = txt,
                "enabled" => enabled = true,
                "vcpus" => vcpus = txt.parse().unwrap_or(4),
                "vcpu_type" => vcpu_type = txt,
                "kernel_params" => kernel_params = txt,
                "service_url" => service_url = txt,
                _ => {}
            }
        }
    }
    
    // Rebuild full kernel params with service URL
    let base_params = kernel_params.replace(&format!("rd.attest.url={}", service_url), "").trim().to_string();
    let full_params = if base_params.is_empty() {
        format!("rd.attest.url={}", service_url)
    } else {
        format!("{} rd.attest.url={}", base_params, service_url)
    };
    
    // If files were updated or service URL changed, regenerate blocks
    if files_updated || !service_url.is_empty() {
        if let Err(e) = snpguest_wrapper::generate_measurement_and_block(
            &artifact_dir.join("firmware-code.fd"),
            &artifact_dir.join("vmlinuz"),
            &artifact_dir.join("initrd.img"),
            &full_params,
            vcpus,
            &vcpu_type,
            &artifact_dir.join("id-block-key.pem"),
            &artifact_dir.join("id-auth-key.pem"),
            &artifact_dir,
        ) {
            return Html(format!("<h1>Error Regenerating Measurement</h1><p>{}</p>", e)).into_response();
        }
        
        // Update key digests if keys were changed
        if files_updated {
            if let Ok(id_digest) = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-block-key.pem")) {
                if let Ok(auth_digest) = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-auth-key.pem")) {
                    let mut active: vm::ActiveModel = vm.clone().into();
                    active.id_key_digest = Set(id_digest);
                    active.auth_key_digest = Set(auth_digest);
                    active.kernel_params = Set(full_params);
                    active.update(&db).await.unwrap();
                    return Redirect::to(&format!("/view/{}", id)).into_response();
                }
            }
        }
    }
    
    // Update DB
    let mut active: vm::ActiveModel = vm.into();
    active.os_name = Set(os_name);
    active.secret = Set(secret);
    active.enabled = Set(enabled);
    active.kernel_params = Set(full_params);
    active.update(&db).await.unwrap();
    Redirect::to(&format!("/view/{}", id)).into_response()
}

pub async fn toggle_enabled(
    Path(id): Path<String>,
    Extension(db): Extension<DatabaseConnection>,
) -> impl IntoResponse {
    if let Some(vm) = vm::Entity::find_by_id(id).one(&db).await.unwrap() {
        let mut active: vm::ActiveModel = vm.into();
        active.enabled = Set(!active.enabled.clone().unwrap_or(true));
        active.update(&db).await.unwrap();
    }
    Redirect::to("/")
}

pub async fn delete_action(Path(id): Path<String>, Extension(db): Extension<DatabaseConnection>) -> impl IntoResponse {
    vm::Entity::delete_by_id(&id).exec(&db).await.unwrap();
    let _ = fs::remove_dir_all(PathBuf::from("artifacts").join(id));
    Redirect::to("/")
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
            let headers = [("Content-Type", "application/octet-stream"), ("Content-Disposition", format!("attachment; filename=\"{}\"", file_name).as_str())];
            (headers, body).into_response()
        },
        Err(_) => "File not found".into_response()
    }
}
