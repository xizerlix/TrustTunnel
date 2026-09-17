use serde::de::{self, Deserializer, Visitor};
use std::fmt;
use std::marker::PhantomData;

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
}
