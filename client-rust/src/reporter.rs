use crate::collector::ReportPayload;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

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

    fn generate_signature(&self, body: &[u8], ts: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(self.shared_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(body);
        mac.update(ts.to_string().as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }
}
