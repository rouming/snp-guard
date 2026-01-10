use tonic::transport::Channel;
use common::snpguard::{
    management_service_client::ManagementServiceClient,
    *,
};

// Create a gRPC client connected to localhost
pub async fn create_management_client() -> Result<ManagementServiceClient<Channel>, Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;
    Ok(ManagementServiceClient::new(channel))
}

pub async fn list_records() -> Result<Vec<AttestationRecord>, Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(ListRecordsRequest {});
    let response = client.list_records(request).await?;
    Ok(response.into_inner().records)
}

pub async fn get_record(id: String) -> Result<Option<AttestationRecord>, Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(GetRecordRequest { id });
    let response = client.get_record(request).await?;
    Ok(response.into_inner().record)
}

pub async fn create_record(
    os_name: String,
    id_key: Option<Vec<u8>>,
    auth_key: Option<Vec<u8>>,
    firmware: Option<Vec<u8>>,
    kernel: Option<Vec<u8>>,
    initrd: Option<Vec<u8>>,
    kernel_params: String,
    vcpus: u32,
    vcpu_type: String,
    service_url: String,
    secret: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(CreateRecordRequest {
        os_name,
        id_key: id_key.unwrap_or_default(),
        auth_key: auth_key.unwrap_or_default(),
        firmware: firmware.unwrap_or_default(),
        kernel: kernel.unwrap_or_default(),
        initrd: initrd.unwrap_or_default(),
        kernel_params,
        vcpus: vcpus as u32,
        vcpu_type,
        service_url,
        secret,
    });
    let response = client.create_record(request).await?;
    let result = response.into_inner();
    if let Some(error) = result.error_message {
        return Err(error.into());
    }
    Ok(result.id)
}

pub async fn update_record(
    id: String,
    os_name: Option<String>,
    id_key: Option<Vec<u8>>,
    auth_key: Option<Vec<u8>>,
    firmware: Option<Vec<u8>>,
    kernel: Option<Vec<u8>>,
    initrd: Option<Vec<u8>>,
    kernel_params: Option<String>,
    vcpus: Option<u32>,
    vcpu_type: Option<String>,
    service_url: Option<String>,
    secret: Option<String>,
    enabled: Option<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(UpdateRecordRequest {
        id,
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
    });
    let response = client.update_record(request).await?;
    let result = response.into_inner();
    if !result.success {
        if let Some(error) = result.error_message {
            return Err(error.into());
        }
    }
    Ok(())
}

pub async fn delete_record(id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(DeleteRecordRequest { id });
    let response = client.delete_record(request).await?;
    let result = response.into_inner();
    if !result.success {
        if let Some(error) = result.error_message {
            return Err(error.into());
        }
    }
    Ok(())
}

pub async fn toggle_enabled(id: String) -> Result<bool, Box<dyn std::error::Error>> {
    let mut client = create_management_client().await?;
    let request = tonic::Request::new(ToggleEnabledRequest { id });
    let response = client.toggle_enabled(request).await?;
    let result = response.into_inner();
    if let Some(error) = result.error_message {
        return Err(error.into());
    }
    Ok(result.enabled)
}