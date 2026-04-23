use crate::core::string_map::{StringMap, StringMapExt};
use rand::RngExt;

pub const CHECK_MARK: i32 = -1;

static DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

#[derive(Clone)]
pub struct PaddingFactory {
    scheme: StringMap,
    raw_scheme: Vec<u8>,
    stop: u32,
    md5: String,
}

impl Default for PaddingFactory {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap()
    }
}

impl PaddingFactory {
    pub fn new(raw_scheme: &[u8]) -> Option<Self> {
        let scheme = StringMap::from_bytes(raw_scheme);
        if scheme.is_empty() {
            return None;
        }

        let stop = scheme.get("stop")?.parse::<u32>().ok()?;
        let md5 = format!("{:x}", md5::compute(raw_scheme));

        Some(Self {
            scheme,
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
        })
    }

    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut pkt_sizes = Vec::new();

        if let Some(s) = self.scheme.get(&pkt.to_string()) {
            let s_ranges: Vec<&str> = s.split(',').collect();

            for s_range in s_ranges {
                if s_range == "c" {
                    pkt_sizes.push(CHECK_MARK);
                } else if let Some((min_str, max_str)) = s_range.split_once('-')
                    && let (Ok(min), Ok(max)) = (min_str.parse::<i64>(), max_str.parse::<i64>())
                {
                    let (min, max) = (min.min(max), min.max(max));
                    if min > 0 && max > 0 {
                        if min == max {
                            pkt_sizes.push(min as i32);
                        } else {
                            let mut rng = rand::rng();
                            let size = rng.random_range(min..=max);
                            pkt_sizes.push(size as i32);
                        }
                    }
                }
            }
        }

        pkt_sizes
    }

    pub fn md5(&self) -> &str {
        &self.md5
    }

    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }
}
