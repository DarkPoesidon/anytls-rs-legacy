use std::collections::HashMap;

pub type StringMap = HashMap<String, String>;

pub trait StringMapExt {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Self;
}

impl StringMapExt for StringMap {
    fn to_bytes(&self) -> Vec<u8> {
        let lines: Vec<String> = self.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        lines.join("\n").into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Self {
        let content = String::from_utf8_lossy(data);
        let mut map = HashMap::new();

        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }

        map
    }
}
