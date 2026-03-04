use ipnet::IpNet;
use std::net::IpAddr;

/// Check if an IP address string is contained in any of the given CIDR ranges.
pub fn ip_in_ranges(ip_str: &str, ranges: &[IpNet]) -> bool {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    ranges.iter().any(|net| net.contains(&ip))
}

/// Parse a list of CIDR strings into IpNet values.
pub fn parse_cidrs(cidrs: &[String]) -> Result<Vec<IpNet>, String> {
    cidrs
        .iter()
        .map(|s| s.parse::<IpNet>().map_err(|e| format!("Invalid CIDR '{}': {}", s, e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_range() {
        let ranges = parse_cidrs(&["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]).unwrap();
        assert!(ip_in_ranges("10.0.1.50", &ranges));
        assert!(ip_in_ranges("192.168.1.1", &ranges));
        assert!(!ip_in_ranges("203.0.113.1", &ranges));
    }

    #[test]
    fn test_invalid_ip() {
        let ranges = parse_cidrs(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(!ip_in_ranges("not-an-ip", &ranges));
    }

    #[test]
    fn test_ipv6_address() {
        let ranges = parse_cidrs(&["2001:db8::/32".to_string()]).unwrap();
        assert!(ip_in_ranges("2001:db8::1", &ranges));
        assert!(!ip_in_ranges("2001:db9::1", &ranges));
    }

    #[test]
    fn test_ipv6_loopback() {
        let ranges = parse_cidrs(&["::1/128".to_string()]).unwrap();
        assert!(ip_in_ranges("::1", &ranges));
        assert!(!ip_in_ranges("::2", &ranges));
    }

    #[test]
    fn test_mixed_ipv4_ipv6_ranges() {
        let ranges = parse_cidrs(&[
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
        ])
        .unwrap();
        assert!(ip_in_ranges("10.0.0.1", &ranges));
        assert!(ip_in_ranges("2001:db8::1", &ranges));
        assert!(!ip_in_ranges("192.168.0.1", &ranges));
    }

    #[test]
    fn test_empty_ranges() {
        let ranges: Vec<IpNet> = vec![];
        assert!(!ip_in_ranges("10.0.0.1", &ranges));
    }

    #[test]
    fn test_invalid_cidr_parse() {
        assert!(parse_cidrs(&["not-a-cidr".to_string()]).is_err());
    }
}
