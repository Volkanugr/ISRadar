//! Bounded parser for the HEAD-only connection-continuity check; no response bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHead {
    pub version: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl HttpHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
    pub fn allows_reuse(&self) -> bool {
        let connection = self.header("connection").unwrap_or("");
        if connection
            .split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("close"))
        {
            return false;
        }
        self.version == "HTTP/1.1"
            || connection
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("keep-alive"))
    }
}

pub fn parse(bytes: &[u8]) -> Result<HttpHead, String> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\r\n\r\n") {
        return Err("incomplete or oversized HTTP response head".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF8 HTTP response head")?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut status = lines.next().ok_or("missing HTTP status")?.splitn(3, ' ');
    let version = status.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("unsupported HTTP version".into());
    }
    let code = status.next().ok_or("missing HTTP status")?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid HTTP status".into());
    }
    let code: u16 = code.parse().map_err(|_| "invalid HTTP status")?;
    if !(100..600).contains(&code) {
        return Err("invalid HTTP response status".into());
    }
    if !status
        .next()
        .unwrap_or("")
        .bytes()
        .all(|b| b == b'\t' || (32..=126).contains(&b))
    {
        return Err("invalid HTTP reason phrase".into());
    }
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= 64 {
            return Err("too many HTTP headers".into());
        }
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err("invalid HTTP header".into());
        }
        if name.eq_ignore_ascii_case("connection")
            && headers
                .iter()
                .any(|(key, _): &(String, String)| key.eq_ignore_ascii_case(name))
        {
            return Err("ambiguous Connection headers".into());
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    Ok(HttpHead {
        version: version.into(),
        status: code,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_persistent_and_closing_connections() {
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap()
            .allows_reuse());
        assert!(!parse(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap()
            .allows_reuse());
        assert!(!parse(b"HTTP/1.0 200 OK\r\n\r\n").unwrap().allows_reuse());
        assert!(parse(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n")
            .unwrap()
            .allows_reuse());
    }
    #[test]
    fn rejects_ambiguous_or_malformed_heads() {
        for value in [
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n folded: value\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 099 Invalid\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nBODY",
            b"HTTP/1.1 200 OK\r\nX: value\nInjected: yes\r\n\r\n",
            b"HTTP/1.1 200 OK\nInjected: yes\r\n\r\n",
        ] {
            assert!(parse(value).is_err());
        }
        assert!(parse(&vec![b'x'; 4097]).is_err());
    }
}
