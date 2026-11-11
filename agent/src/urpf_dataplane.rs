//! Compile snapshot uRPF rules with explicit interface scope and longest-prefix
//! precedence. The control-plane exception is limited to configured neighbor
//! addresses and local BGP TCP endpoints; ignored route networks are NOT broad
//! packet exemptions. An empty SAV table still rejects data on configured links.
use crate::{
    compact_prefixes, nft_string, parse_prefix, push_nft_element_chunks, LinkState, SavRule,
    NFT_CHAIN, NFT_TABLE,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

fn version(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        4
    } else {
        6
    }
}

pub(crate) fn compile(
    app: &str,
    family: u8,
    rules: &[&SavRule],
    links: &BTreeMap<String, LinkState>,
) -> Result<Vec<String>, String> {
    let (kind, expr, nfproto) = match family {
        4 => ("ipv4_addr", "ip", "ipv4"),
        6 => ("ipv6_addr", "ip6", "ipv6"),
        _ => return Err("invalid uRPF address family".into()),
    };
    if !matches!(app, "strict_urpf" | "loose_urpf") {
        return Err("uRPF compiler called for another mechanism".into());
    }
    let mut peers = BTreeSet::new();
    for link in links.values() {
        let (Some(remote), Some(local)) = (&link.remote_ip, &link.local_ip) else {
            return Err("uRPF scope requires configured local and remote addresses".into());
        };
        let remote: IpAddr = remote.parse().map_err(|_| "invalid neighbor IP")?;
        let local: IpAddr = local.parse().map_err(|_| "invalid local IP")?;
        if version(remote) != version(local) {
            return Err("neighbor address families differ".into());
        }
        if version(remote) != family {
            continue;
        }
        if link.interface_name.is_empty()
            || link.interface_name == "lo"
            || link.interface_name.len() > 15
        {
            return Err("invalid data-plane interface scope".into());
        }
        peers.insert((link.interface_name.clone(), remote, local));
    }
    if peers.is_empty() {
        return Ok(Vec::new()); // This family is not enabled on any configured link.
    }
    let chain = format!("sav_urpf{family}");
    let ingress = format!("sav_ingress{family}");
    let interfaces: Vec<String> = peers
        .iter()
        .map(|(i, _, _)| nft_string(i))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut out = vec![
        format!("add chain inet {NFT_TABLE} {chain} {{ }}"),
        format!("add set inet {NFT_TABLE} {ingress} {{ type ifname; }}"),
    ];
    push_nft_element_chunks(&mut out, &ingress, &interfaces);
    out.push(format!("add rule inet {NFT_TABLE} {NFT_CHAIN} meta nfproto {nfproto} iifname @{ingress} jump {chain}"));
    for (iface, remote, local) in peers {
        for port in ["sport", "dport"] {
            out.push(format!("add rule inet {NFT_TABLE} {chain} iifname {} {expr} saddr {remote} {expr} daddr {local} tcp {port} 179 counter return", nft_string(&iface)));
        }
        if family == 6 {
            // RFC 4861 NS/NA may use the interface address, not just fe80::/10.
            // Insert before the input-chain jump: this exception must not admit
            // forwarded traffic. The receiving IPv6 stack validates ND targets,
            // checksums and message structure; this is not ND authentication.
            out.push(format!("insert rule inet {NFT_TABLE} {NFT_CHAIN}_input iifname {} ip6 saddr {remote} ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} icmpv6 code 0 counter return", nft_string(&iface)));
        }
    }
    if family == 6 {
        // Neighbor discovery is link-local control, not evidence of SAV acceptance.
        out.push(format!("add rule inet {NFT_TABLE} {chain} ip6 hoplimit 255 ip6 saddr {{ ::, fe80::/10 }} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} counter return"));
    }
    if app == "loose_urpf" {
        let prefixes = compact_prefixes(rules.iter().map(|r| r.prefix.clone()).collect());
        if !prefixes.is_empty() {
            let set = format!("sav_loose{family}");
            out.push(format!(
                "add set inet {NFT_TABLE} {set} {{ type {kind}; flags interval; auto-merge; }}"
            ));
            push_nft_element_chunks(&mut out, &set, &prefixes);
            out.push(format!(
                "add rule inet {NFT_TABLE} {chain} {expr} saddr @{set} counter return"
            ));
        }
    } else {
        // Never union broad and more-specific routes across interfaces: that can
        // admit a source through a broad route despite a different longest match.
        let mut groups: BTreeMap<u8, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
        for rule in rules {
            let p = parse_prefix(&rule.prefix).ok_or("invalid SAV prefix")?;
            if version(p.addr) != family
                || rule.interface_name == "*"
                || rule.interface_name.is_empty()
            {
                return Err("invalid strict-uRPF rule".into());
            }
            groups
                .entry(p.len)
                .or_default()
                .entry(format!("{}/{}", p.addr, p.len))
                .or_default()
                .insert(rule.interface_name.clone());
        }
        for (length, entries) in groups.iter().rev() {
            let known = format!("sav_k{family}_{length}");
            let allowed = format!("sav_a{family}_{length}");
            out.push(format!(
                "add set inet {NFT_TABLE} {known} {{ type {kind}; flags interval; auto-merge; }}"
            ));
            out.push(format!(
                "add set inet {NFT_TABLE} {allowed} {{ type {kind} . ifname; flags interval; }}"
            ));
            push_nft_element_chunks(
                &mut out,
                &known,
                &entries.keys().cloned().collect::<Vec<_>>(),
            );
            let pairs = entries
                .iter()
                .flat_map(|(p, interfaces)| {
                    interfaces
                        .iter()
                        .map(move |i| format!("{p} . {}", nft_string(i)))
                })
                .collect::<Vec<_>>();
            push_nft_element_chunks(&mut out, &allowed, &pairs);
            out.push(format!("add rule inet {NFT_TABLE} {chain} {expr} saddr . iifname @{allowed} counter return"));
            out.push(format!(
                "add rule inet {NFT_TABLE} {chain} {expr} saddr @{known} counter drop"
            ));
        }
    }
    out.push(format!("add rule inet {NFT_TABLE} {chain} counter drop"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links(family: u8) -> BTreeMap<String, LinkState> {
        let (local, remote) = if family == 4 {
            ("10.0.0.1", "10.0.0.2")
        } else {
            ("fec::1", "fec::2")
        };
        BTreeMap::from([(
            "dsav_1_2".into(),
            LinkState {
                protocol_name: "dsav_1_2".into(),
                interface_name: "eth_2".into(),
                link_type: None,
                local_ip: Some(local.into()),
                remote_ip: Some(remote.into()),
                remote_id: Some("2".into()),
                is_interior: None,
                remote_as: Some(4200000002),
                local_role: None,
                remote_role: None,
                remote_location: None,
                status: false,
                events: 0,
                link_state_changes: 0,
                last_seen: None,
                last_msg_type: None,
            },
        )])
    }

    fn rule(prefix: &str, interface: &str) -> SavRule {
        SavRule {
            prefix: prefix.into(),
            interface_name: interface.into(),
            source_app: "strict_urpf".into(),
            origin: -1,
            is_interior: false,
        }
    }

    #[test]
    fn empty_table_drops_on_configured_interfaces() {
        for app in ["strict_urpf", "loose_urpf"] {
            for family in [4, 6] {
                let lines = compile(app, family, &[], &links(family)).unwrap();
                assert_eq!(
                    lines.last().unwrap(),
                    &format!("add rule inet savop sav_urpf{family} counter drop")
                );
                assert!(lines.iter().any(|x| x.contains("iifname @sav_ingress")));
                assert!(!lines.iter().any(|x| x.contains("eth0")));
            }
        }
    }

    #[test]
    fn loose_wildcards_still_install_an_allow_set_and_default_drop() {
        let r = rule("198.18.0.0/24", "*");
        let lines = compile("loose_urpf", 4, &[&r], &links(4))
            .unwrap()
            .join("\n");
        assert!(lines.contains("198.18.0.0/24"));
        assert!(lines.contains("ip saddr @sav_loose4 counter return"));
        assert!(lines.ends_with("counter drop"));
    }

    #[test]
    fn longest_prefix_precedes_broad_route() {
        for (family, broad, narrow, host) in [
            (4, "198.18.0.0/16", "198.18.0.0/24", "198.18.0.1/32"),
            (6, "fd42:2400::/32", "fd42:2400::/64", "fd42:2400::1/128"),
        ] {
            let a = rule(broad, "eth_1");
            let b = rule(narrow, "eth_2");
            let c = rule(host, "endpoint");
            let lines = compile("strict_urpf", family, &[&a, &b, &c], &links(family)).unwrap();
            let index = |s: &str| lines.iter().position(|line| line.contains(s)).unwrap();
            assert!(index(host) < index(narrow));
            assert!(index(narrow) < index(broad));
            assert_eq!(
                lines.iter().filter(|x| x.ends_with("counter drop")).count(),
                4
            );
        }
    }

    #[test]
    fn same_prefix_multiple_interfaces_are_not_lost() {
        let a = rule("198.18.0.0/24", "eth_1");
        let b = rule("198.18.0.0/24", "eth_2");
        let text = compile("strict_urpf", 4, &[&a, &b], &links(4))
            .unwrap()
            .join("\n");
        assert!(text.contains("198.18.0.0/24 . \"eth_1\""));
        assert!(text.contains("198.18.0.0/24 . \"eth_2\""));
    }

    #[test]
    fn malformed_scope_and_wildcard_strict_are_rejected() {
        let mut peer = links(4);
        peer.values_mut().next().unwrap().remote_ip = None;
        assert!(compile("strict_urpf", 4, &[], &peer).is_err());
        assert!(compile("strict_urpf", 4, &[&rule("198.18.0.0/24", "*")], &links(4)).is_err());
    }

    #[test]
    fn opposite_family_has_no_implicit_filter() {
        assert!(compile("strict_urpf", 6, &[], &links(4))
            .unwrap()
            .is_empty());
        assert!(compile("loose_urpf", 4, &[], &links(6)).unwrap().is_empty());
    }

    #[test]
    fn bgp_exception_is_not_a_broad_network_bypass() {
        let text = compile("strict_urpf", 4, &[], &links(4))
            .unwrap()
            .join("\n");
        assert!(
            text.contains("iifname \"eth_2\" ip saddr 10.0.0.2 ip daddr 10.0.0.1 tcp dport 179")
        );
        assert!(!text.contains("10.0.0.0/8"));
    }

    #[test]
    fn configured_neighbor_nd_is_input_only_and_not_general_data_bypass() {
        for app in ["strict_urpf", "loose_urpf"] {
            let lines = compile(app, 6, &[], &links(6)).unwrap();
            let inserted: Vec<_> = lines
                .iter()
                .filter(|line| line.starts_with("insert rule"))
                .collect();
            assert_eq!(inserted.len(), 1);
            let rule = inserted[0];
            assert!(rule.contains("savagent_input iifname \"eth_2\" ip6 saddr fec::2 "));
            assert!(rule.contains("ip6 hoplimit 255"));
            assert!(rule.contains("nd-neighbor-solicit, nd-neighbor-advert"));
            assert!(rule.contains("icmpv6 code 0 counter return"));
            assert!(!rule.contains("_forward"));
            assert!(!rule.contains("fec::/16"));
            assert!(!rule.contains("udp"));
        }
    }

    #[test]
    fn ipv4_does_not_install_neighbor_discovery_exception() {
        let lines = compile("strict_urpf", 4, &[], &links(4)).unwrap();
        assert!(!lines.iter().any(|line| line.starts_with("insert rule")));
    }
}
