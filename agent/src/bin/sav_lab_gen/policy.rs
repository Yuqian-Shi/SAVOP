//! Explicit experimental policy, not a reconstruction of operators' policies.
//! Legacy inputs are unchanged; new inputs fail closed on incomplete relations.
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

pub type Roles = BTreeMap<(String, String), (&'static str, &'static str)>;

fn invalid(text: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text)
}

pub fn parse(
    base: &Value,
    devices: &Map<String, Value>,
    links: &[Value],
) -> io::Result<Option<Roles>> {
    let Some(policy) = base.get("routing_policy") else {
        return Ok(None);
    };
    if policy.get("model").and_then(Value::as_str) != Some("customer-provider-v1") {
        return Err(invalid("unsupported explicit routing_policy model"));
    }
    let entries = policy
        .get("links")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("routing_policy.links must be an array"))?;
    let mut expected = BTreeSet::new();
    let mut physical = BTreeSet::new();
    for link in links {
        let a = link
            .get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("policy link node must be string"))?;
        let b = link
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("policy link node must be string"))?;
        if a == b || !devices.contains_key(a) || !devices.contains_key(b) {
            return Err(invalid("invalid policy link endpoints"));
        }
        let pair = if a < b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        };
        if !physical.insert(pair.clone()) {
            return Err(invalid("duplicate physical policy link"));
        }
        // Intra-AS iBGP links have no customer/peer/provider relationship.
        // They remain part of the physical graph but need no export-policy row.
        if devices[a].get("as") == devices[b].get("as") {
            continue;
        }
        expected.insert(pair);
    }
    let mut found = BTreeSet::new();
    let mut roles = BTreeMap::new();
    for entry in entries {
        let a = entry
            .get("a")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing policy endpoint a"))?;
        let b = entry
            .get("b")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing policy endpoint b"))?;
        let pair = if a < b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        };
        if !expected.contains(&pair) || !found.insert(pair) {
            return Err(invalid("extra or duplicate routing policy link"));
        }
        let (ra, rb) = match entry.get("relationship").and_then(Value::as_str) {
            Some("p2p") if entry.get("provider").is_none_or(Value::is_null) => ("peer", "peer"),
            Some("p2c") => match entry.get("provider").and_then(Value::as_str) {
                Some(p) if p == a => ("provider", "customer"),
                Some(p) if p == b => ("customer", "provider"),
                _ => return Err(invalid("p2c provider must be a link endpoint")),
            },
            _ => {
                return Err(invalid(
                    "unknown, conflicting or malformed relationship cannot compile",
                ))
            }
        };
        roles.insert((a.to_string(), b.to_string()), (ra, rb));
        roles.insert((b.to_string(), a.to_string()), (rb, ra));
    }
    if found != expected {
        return Err(invalid(
            "every physical link needs an explicit routing relationship",
        ));
    }
    Ok(Some(roles))
}

pub fn channel(family: &str, remote_role: &str, customer_protocols: &[String]) -> Vec<String> {
    let preference = match remote_role {
        "customer" => 300,
        "peer" => 200,
        "provider" => 100,
        _ => unreachable!("roles validated before generation"),
    };
    let mut lines = vec![
        format!("  {family} {{"),
        format!("    import filter {{ bgp_local_pref = {preference}; accept; }};"),
        "    export filter {".to_string(),
        "      if source = RTS_STATIC then accept;".to_string(),
    ];
    if remote_role == "customer" {
        lines.push("      if source = RTS_BGP then accept;".to_string());
    } else {
        for proto in customer_protocols {
            // Node IDs are validated numeric; no untrusted filter text is interpolated.
            lines.push(format!("      if proto = \"{proto}\" then accept;"));
        }
    }
    lines.extend([
        "      reject;".to_string(),
        "    };".to_string(),
        "    next hop self on;".to_string(),
        "  };".to_string(),
    ]);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn input() -> Value {
        json!({"devices":{"1":{"as":4200000001u64},"2":{"as":4200000002u64},"3":{"as":4200000003u64}},
            "links":[["1","2","dsav"],["2","3","dsav"]],
            "routing_policy":{"model":"customer-provider-v1","links":[
              {"a":"1","b":"2","relationship":"p2c","provider":"1"},
              {"a":"2","b":"3","relationship":"p2p","provider":null}]}})
    }
    fn parse_input(v: &Value) -> io::Result<Option<Roles>> {
        parse(
            v,
            v["devices"].as_object().unwrap(),
            v["links"].as_array().unwrap(),
        )
    }
    #[test]
    fn directions() {
        let r = parse_input(&input()).unwrap().unwrap();
        assert_eq!(r[&("1".into(), "2".into())], ("provider", "customer"));
        assert_eq!(r[&("2".into(), "1".into())], ("customer", "provider"));
        assert_eq!(r[&("2".into(), "3".into())], ("peer", "peer"));
    }
    #[test]
    fn missing_relation() {
        let mut v = input();
        v["routing_policy"]["links"].as_array_mut().unwrap().pop();
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn unknown_is_not_peer() {
        let mut v = input();
        v["routing_policy"]["links"][0]["relationship"] = json!("unknown");
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn invalid_provider() {
        let mut v = input();
        v["routing_policy"]["links"][0]["provider"] = json!("3");
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn duplicate_relation() {
        let mut v = input();
        let e = v["routing_policy"]["links"][0].clone();
        v["routing_policy"]["links"].as_array_mut().unwrap().push(e);
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn legacy_unchanged() {
        let mut v = input();
        v.as_object_mut().unwrap().remove("routing_policy");
        assert!(parse_input(&v).unwrap().is_none());
    }
    #[test]
    fn same_as_refused() {
        let mut v = input();
        v["devices"]["2"]["as"] = v["devices"]["1"]["as"].clone();
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn no_peer_provider_transit() {
        for role in ["peer", "provider"] {
            let text = channel("ipv4", role, &["dsav_1_2".into()]).join("\n");
            assert!(text.contains("proto = \"dsav_1_2\""));
            assert!(!text.contains("source = RTS_BGP then accept"));
            assert!(text.contains("reject;"));
        }
    }

    #[test]
    fn mixed_ibgp_and_ebgp_links_require_policy_only_for_ebgp() {
        let mut v = input();
        v["devices"]["4"] = json!({"as":4200000003u64});
        v["links"]
            .as_array_mut()
            .unwrap()
            .push(json!(["3", "4", "dsav"]));
        let roles = parse_input(&v).unwrap().unwrap();
        assert_eq!(roles[&("1".into(), "2".into())], ("provider", "customer"));
        assert_eq!(roles[&("2".into(), "3".into())], ("peer", "peer"));
        assert!(!roles.contains_key(&("3".into(), "4".into())));
    }

    #[test]
    fn duplicate_intra_as_physical_link_is_rejected() {
        let mut v = input();
        v["devices"]["4"] = json!({"as":4200000003u64});
        v["links"]
            .as_array_mut()
            .unwrap()
            .extend([json!(["3", "4", "dsav"]), json!(["4", "3", "dsav"])]);
        assert!(parse_input(&v).is_err());
    }
    #[test]
    fn customer_exports_bgp() {
        let text = channel("ipv6", "customer", &[]).join("\n");
        assert!(text.contains("bgp_local_pref = 300"));
        assert!(text.contains("source = RTS_BGP then accept"));
    }
}
