use crate::panel_sync::TrafficAuditPtr;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct PanelSyncConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webapi_url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webapi_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(deserialize = "api_update_time", serialize = "api_update_time"))]
    pub api_update_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct SyncUser {
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    client_id: Option<Uuid>,
    #[serde(default = "default_true")]
    enable: bool,
}

fn default_true() -> bool {
    true
}

fn deserialize_optional_uuid<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Uuid::parse_str(&s).ok()),
        _ => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct PanelSyncClient {
    config: PanelSyncConfig,
    client: reqwest::Client,
    reported_traffic: HashMap<Uuid, (u64, u64)>,
}

impl PanelSyncClient {
    pub fn new(config: PanelSyncConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            reported_traffic: HashMap::new(),
        }
    }

    pub async fn run(mut self, traffic_audit: TrafficAuditPtr, quit: CancellationToken) -> std::io::Result<()> {
        let interval_secs = self.config.api_update_interval_secs.unwrap_or(10).max(5);
        self.sync_once(&traffic_audit).await.ok();
        self.report_traffic_once(&traffic_audit).await.ok();

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = quit.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(e) = self.sync_once(&traffic_audit).await {
                        log::warn!("panel sync failed: {e}");
                    }
                    if let Err(e) = self.report_traffic_once(&traffic_audit).await {
                        log::warn!("panel traffic report failed: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    async fn sync_once(&mut self, traffic_audit: &TrafficAuditPtr) -> std::io::Result<()> {
        let users = self.fetch_sync_payload().await?;

        let existing_clients = traffic_audit.lock().await.get_client_list();
        let mut seen_clients = HashSet::new();

        log::trace!("syncing users from panel: {:?}", users);

        for user in users {
            if let Some(client_id) = user.client_id {
                seen_clients.insert(client_id);
                let mut audit = traffic_audit.lock().await;
                audit.add_client(&client_id);
                audit.set_enable_of(&client_id, user.enable);
            } else {
                log::warn!("ignored panel sync user entry with missing or invalid client_id: {user:?}");
            }
        }

        for client_id in existing_clients {
            if !seen_clients.contains(&client_id) {
                traffic_audit.lock().await.remove_client(&client_id);
                self.reported_traffic.remove(&client_id);
            }
        }

        Ok(())
    }

    async fn report_traffic_once(&mut self, traffic_audit: &TrafficAuditPtr) -> std::io::Result<()> {
        let client_ids = traffic_audit.lock().await.get_client_list();
        let mut payload = Vec::new();
        let mut current_traffic = HashMap::new();

        for client_id in client_ids {
            let client_id_clone = client_id;
            let (upstream, downstream) = {
                let audit = traffic_audit.lock().await;
                let upstream = audit.get_upstream_traffic_of(&client_id);
                let downstream = audit.get_downstream_traffic_of(&client_id);
                (upstream, downstream)
            };

            let last_reported = self.reported_traffic.get(&client_id).copied().unwrap_or((0, 0));
            let delta_upstream = upstream.saturating_sub(last_reported.0);
            let delta_downstream = downstream.saturating_sub(last_reported.1);

            if delta_upstream == 0 && delta_downstream == 0 {
                continue;
            }

            current_traffic.insert(client_id_clone, (upstream, downstream));

            let mut record = serde_json::Map::new();
            record.insert("client_id".to_string(), serde_json::json!(client_id_clone));
            record.insert("u".to_string(), serde_json::json!(delta_upstream));
            record.insert("d".to_string(), serde_json::json!(delta_downstream));

            payload.push(serde_json::Value::Object(record));
        }

        if payload.is_empty() {
            return Ok(());
        }

        let body = serde_json::json!({
            "data": payload,
        });

        use std::io::Error;
        let node_id = self.config.node_id.ok_or_else(|| Error::other("panel sync node_id not set"))?;
        // url like: {webapi_url}/mod_mu/users/traffic?key={webapi_token}&node_id={node_id}
        let url = self.build_url("users/traffic", &[("node_id", node_id.to_string())])?;
        let response = self.client.post(url).json(&body).send().await.map_err(std::io::Error::other)?;
        let r: serde_json::Value = self.parse_payload(response).await?;

        log::trace!("reported traffic post {body:?} response: {r:?}");

        for (client_id, &(upstream, downstream)) in &current_traffic {
            self.reported_traffic.insert(*client_id, (upstream, downstream));
        }

        Ok(())
    }

    async fn fetch_sync_payload(&self) -> std::io::Result<Vec<SyncUser>> {
        use std::io::Error;
        let node_id = self.config.node_id.ok_or_else(|| Error::other("panel sync node_id not set"))?;
        // url like: {webapi_url}/mod_mu/users?key={webapi_token}&node_id={node_id}
        let url = self.build_url("users", &[("node_id", node_id.to_string())])?;
        let response = self.client.get(url).send().await.map_err(Error::other)?;
        let users = self.parse_payload(response).await?;
        Ok(users)
    }

    async fn parse_payload<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> std::io::Result<T> {
        if response.status() != 200 {
            return Err(std::io::Error::other(format!("{}", response.status())));
        }

        let value = response.json::<serde_json::Value>().await.map_err(std::io::Error::other)?;
        if value.get("ret").and_then(|v| v.as_i64()).unwrap_or_default() == 0 {
            return Err(std::io::Error::other(format!("Wrong data: {value:?}")));
        }

        let data = value.get("data").cloned().unwrap_or(value.clone());
        serde_json::from_value(data.clone()).map_err(|e| std::io::Error::other(format!("{e}: {data:?}")))
    }

    /// build url like: {webapi_url}/mod_mu/{action}?key={webapi_token}&{params}
    fn build_url(&self, action: &str, params: &[(&str, String)]) -> std::io::Result<String> {
        let base = self
            .config
            .webapi_url
            .as_ref()
            .ok_or_else(|| std::io::Error::other("panel sync webapi_url not set"))?
            .as_str()
            .trim_end_matches('/')
            .to_string();
        let token = self.config.webapi_token.clone().unwrap_or_default();
        let mut url = format!("{base}/mod_mu/{action}?key={token}");
        for (key, value) in params {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        }
        Ok(url)
    }
}
