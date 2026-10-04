//! Bounded numeric IP-set comparison. No symbolic Windows selectors or DNS.
use std::net::{IpAddr, Ipv4Addr};
const MAX_BYTES: usize = 8192;
const MAX_TERMS: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Interval {
    v6: bool,
    first: u128,
    last: u128,
}
fn address(value: &str) -> Option<(bool, u128)> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => Some((false, u32::from(ip).into())),
        IpAddr::V6(ip) => Some((true, u128::from(ip))),
    }
}
fn prefix(value: &str, v6: bool) -> Option<u32> {
    if !v6 && value.contains('.') {
        let mask = u32::from(value.parse::<Ipv4Addr>().ok()?);
        let inverse = !mask;
        if inverse & inverse.wrapping_add(1) != 0 {
            return None;
        }
        return Some(mask.leading_ones());
    }
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let count = value.parse::<u32>().ok()?;
    (count <= if v6 { 128 } else { 32 }).then_some(count)
}
fn term(value: &str) -> Option<Interval> {
    if let Some((first, last)) = value.split_once('-') {
        let (v6, first) = address(first.trim())?;
        let (last_v6, last) = address(last.trim())?;
        return (v6 == last_v6 && first <= last).then_some(Interval { v6, first, last });
    }
    if let Some((ip, mask)) = value.split_once('/') {
        let (v6, ip) = address(ip.trim())?;
        let count = prefix(mask.trim(), v6)?;
        let bits = if v6 { 128 } else { 32 };
        let maximum = if v6 { u128::MAX } else { u32::MAX.into() };
        let mask = if count == 0 {
            0
        } else {
            (maximum << (bits - count)) & maximum
        };
        let first = ip & mask;
        return Some(Interval {
            v6,
            first,
            last: first | (maximum ^ mask),
        });
    }
    let (v6, ip) = address(value)?;
    Some(Interval {
        v6,
        first: ip,
        last: ip,
    })
}
fn canonical(value: &str) -> Option<Vec<Interval>> {
    if value.len() > MAX_BYTES || !value.is_ascii() {
        return None;
    }
    let value = value.trim();
    if value == "*" {
        return Some(vec![
            Interval {
                v6: false,
                first: 0,
                last: u32::MAX.into(),
            },
            Interval {
                v6: true,
                first: 0,
                last: u128::MAX,
            },
        ]);
    }
    let mut entries = Vec::new();
    for (index, item) in value.split(',').enumerate() {
        if index >= MAX_TERMS || item.trim().is_empty() {
            return None;
        }
        entries.push(term(item.trim())?);
    }
    entries.sort_unstable();
    let mut merged: Vec<Interval> = Vec::new();
    for next in entries {
        if let Some(previous) = merged.last_mut() {
            if previous.v6 == next.v6
                && (next.first <= previous.last || previous.last.checked_add(1) == Some(next.first))
            {
                previous.last = previous.last.max(next.last);
                continue;
            }
        }
        merged.push(next);
    }
    Some(merged)
}
pub(super) fn equivalent(actual: &str, expected: &str) -> bool {
    match (canonical(actual), canonical(expected)) {
        (Some(a), Some(e)) => a == e,
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const LOOPBACK: &str = "127.0.0.0/8,::/127";
    #[test]
    fn accepts_only_identical_numeric_unions() {
        for equivalent_value in [
            "127.0.0.0/255.0.0.0,::/127",
            "::1,127.0.0.0-127.255.255.255,::",
            "::/127,127.128.0.0/9,127.0.0.0/9",
            "127.0.0.0/8,::/128,::1/128,::1",
        ] {
            assert!(equivalent(equivalent_value, LOOPBACK));
        }
    }
    #[test]
    fn rejects_changed_or_invalid_sets() {
        for value in [
            "*",
            "127.0.0.0/7,::/127",
            "127.0.0.0/9,::/127",
            "127.0.0.1,::/127",
            "126.0.0.0/8,::/127",
            "127.0.0.0/8,::/126",
            "127.0.0.0/8,::1",
            "127.0.0.0/255.0.255.0,::/127",
            "127.0.0.0/33,::/127",
            "127.0.0.0/8,::/129",
            "LocalSubnet",
            "DNS",
            "127.0.0.0/8,::%1/127",
            "127.0.0.0-::1",
            "127.255.255.255-127.0.0.0",
            "127.0.0.0/8,",
            ",127.0.0.0/8",
            "127.0.0.0/8,,::/127",
            "127.0.0.0/8,*,::/127",
            "127.0.0.0/8/8,::/127",
            "127.0.0.0/+8,::/127",
            "127.0.0.0/-1,::/127",
        ] {
            assert!(!equivalent(value, LOOPBACK), "unexpected equivalence");
        }
        assert!(!equivalent("LocalSubnet", "LocalSubnet"));
    }
    #[test]
    fn wildcards_require_exact_both_family_universe() {
        assert!(equivalent("*", "0.0.0.0/0,::/0"));
        assert!(!equivalent("*", "0.0.0.0/0"));
        assert!(!equivalent("*", "::/0"));
        assert!(!equivalent("*,127.0.0.1", "*"));
    }
    #[test]
    fn merges_boundaries_without_overflow_or_cross_family_merge() {
        assert!(equivalent(
            "255.255.255.254,255.255.255.255",
            "255.255.255.254/31"
        ));
        assert!(equivalent(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"
        ));
        assert!(equivalent(
            "0.0.0.0/0,::/0,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "*"
        ));
        assert!(!equivalent("0.0.0.0", "::"));
        assert!(!equivalent("127.0.0.1", "::ffff:127.0.0.1"));
    }
    #[test]
    fn parsing_is_bounded() {
        assert!(!equivalent(&" ".repeat(MAX_BYTES + 1), "*"));
        assert!(!equivalent(
            &vec!["127.0.0.1"; MAX_TERMS + 1].join(","),
            "127.0.0.1"
        ));
        assert!(!equivalent("\u{a0}127.0.0.1", "127.0.0.1"));
    }
}
