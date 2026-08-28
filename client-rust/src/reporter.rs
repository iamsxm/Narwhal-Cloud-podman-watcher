use crate::collector::ReportPayload;
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentAction {
    pub id: u64,
    pub action_type: String,
}

#[derive(Debug, Deserialize)]
struct ActionPollResponse {
    #[serde(default)]
    actions: Vec<AgentAction>,
}

pub struct Reporter {
    server_url: String,
    shared_secret: String,
    agent: ureq::Agent,
}

impl Reporter {
    pub fn new(server_url: String, shared_secret: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .timeout_write(Duration::from_secs(15))
            .build();

        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            shared_secret,
            agent,
        }
    }

    pub fn report(&self, payload: &ReportPayload) -> Result<(), String> {
        let body_bytes =
            serde_json::to_vec(payload).map_err(|e| format!("JSON encode error: {}", e))?;
        let ts = payload.timestamp;
        let sig = self.generate_signature(&body_bytes, ts);

        let url = format!("{}/api/v1/report", self.server_url);

        let res = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("X-Timestamp", &ts.to_string())
            .set("X-Signature", &sig)
            .send_bytes(&body_bytes)
            .map_err(|e| format!("HTTP report request failed: {}", e))?;

        if res.status() >= 200 && res.status() < 300 {
            Ok(())
        } else {
            Err(format!("Server returned HTTP {}", res.status()))
        }
    }

    pub fn poll_actions(&self, host_id: &str) -> Result<Vec<AgentAction>, String> {
        let response: ActionPollResponse = self.signed_post(
            "/api/v1/actions/poll",
            &serde_json::json!({"host_id": host_id}),
        )?;
        Ok(response.actions)
    }

    pub fn report_action_result(
        &self,
        action_id: u64,
        host_id: &str,
        succeeded: bool,
        message: &str,
    ) -> Result<(), String> {
        let _: serde_json::Value = self.signed_post(
            "/api/v1/actions/result",
            &serde_json::json!({
                "action_id": action_id,
                "host_id": host_id,
                "status": if succeeded { "succeeded" } else { "failed" },
                "message": message,
            }),
        )?;
        Ok(())
    }

    fn signed_post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<R, String> {
        let body = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
        let timestamp = chrono::Utc::now().timestamp();
        let signature = self.generate_signature(&body, timestamp);
        let url = format!("{}{}", self.server_url, path);
        let response = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("X-Timestamp", &timestamp.to_string())
            .set("X-Signature", &signature)
            .send_bytes(&body)
            .map_err(|error| format!("HTTP action request failed: {}", error))?;
        let response_signature = response
            .header("X-Narwhal-Response-Signature")
            .unwrap_or("")
            .to_string();
        let mut response_body = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut response_body)
            .map_err(|error| format!("action response read failed: {}", error))?;
        let expected = self.generate_signature(&response_body, timestamp);
        if response_signature.is_empty() || response_signature != expected {
            return Err("invalid action response signature".to_string());
        }
        serde_json::from_slice(&response_body)
            .map_err(|error| format!("action response JSON decode failed: {}", error))
    }

    fn generate_signature(&self, body: &[u8], ts: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(self.shared_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(body);
        mac.update(ts.to_string().as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }
}
