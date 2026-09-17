use serde::de::{self, Deserializer, Visitor};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

/// Collect repeated `application/x-www-form-urlencoded` keys.
/// `serde_urlencoded` treats a second `username=` as `duplicate field`.
pub fn form_lists(body: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for (k, v) in form_urlencoded::parse(body.as_bytes()) {
        out.entry(k.into_owned()).or_default().push(v.into_owned());
    }
    out
}

pub fn form_col(map: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    map.get(key).cloned().unwrap_or_default()
}

pub const GIB: f64 = 1_073_741_824.0;

pub fn bytes_to_gib_field(bytes: u64) -> String {
    if bytes == 0 {
        return String::new();
    }
    let gb = bytes as f64 / GIB;
    if (gb - gb.round()).abs() < 0.0005 {
        format!("{}", gb.round() as u64)
    } else {
        let s = format!("{gb:.3}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

pub fn gib_field_to_bytes(s: &str) -> u64 {
    let s = s.trim().replace(',', ".");
    if s.is_empty() {
        return 0;
    }
    let v: f64 = s.parse().unwrap_or(0.0);
    if v <= 0.0 {
        0
    } else {
        (v * GIB).round() as u64
    }
}

/// `application/x-www-form-urlencoded` sends a single field as a string and
/// repeated fields as a sequence. Accept both so a one-row table still saves.
pub fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OneOrMany(PhantomData<Vec<String>>);

    impl<'de> Visitor<'de> for OneOrMany {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or a sequence of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                out.push(item);
            }
            Ok(out)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(OneOrMany(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct Row {
        #[serde(default, deserialize_with = "one_or_many")]
        main_hostname: Vec<String>,
    }

    #[test]
    fn single_string_becomes_vec() {
        let row: Row = serde_urlencoded::from_str("main_hostname=watafa.duckdns.org").unwrap();
        assert_eq!(row.main_hostname, vec!["watafa.duckdns.org"]);
    }

    #[test]
    fn repeated_fields_stay_vec() {
        let row: Row =
            serde_urlencoded::from_str("main_hostname=a.example&main_hostname=b.example").unwrap();
        assert_eq!(row.main_hostname, vec!["a.example", "b.example"]);
    }

    #[test]
    fn missing_field_is_empty() {
        let row: Row = serde_urlencoded::from_str("").unwrap();
        assert!(row.main_hostname.is_empty());
    }

    #[test]
    fn form_lists_keeps_interleaved_keys() {
        let map = form_lists("username=alice&password=a&username=test&password=b");
        assert_eq!(form_col(&map, "username"), vec!["alice", "test"]);
        assert_eq!(form_col(&map, "password"), vec!["a", "b"]);
    }

    #[test]
    fn gib_roundtrip() {
        assert_eq!(bytes_to_gib_field(0), "");
        assert_eq!(gib_field_to_bytes(""), 0);
        assert_eq!(gib_field_to_bytes("1"), 1_073_741_824);
        assert_eq!(bytes_to_gib_field(1_073_741_824), "1");
    }
}
