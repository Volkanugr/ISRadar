//! Bounded SIP framing and transaction validation; no body or routing interpretation.
pub struct ResponseHead {
    pub status: u16,
    pub header_bytes: usize,
    pub body_bytes: Option<usize>,
}

pub fn parse_response_head(
    bytes: &[u8],
    call_id: &str,
    branch: &str,
    method: &str,
    sequence: u32,
) -> Result<ResponseHead, String> {
    if bytes.len() > 4096 {
        return Err("oversized SIP response".into());
    }
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete SIP response head")?;
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid SIP response encoding")?;
    if !text
        .bytes()
        .all(|b| b == b'\r' || b == b'\n' || b == b'\t' || (32..=126).contains(&b))
    {
        return Err("invalid SIP response character".into());
    }
    let mut lines = text.split("\r\n");
    let mut status = lines.next().ok_or("missing SIP status")?.splitn(3, ' ');
    if status.next() != Some("SIP/2.0") {
        return Err("invalid SIP version".into());
    }
    let code = status.next().ok_or("missing SIP status code")?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid SIP status code".into());
    }
    if !status
        .next()
        .unwrap_or("")
        .bytes()
        .all(|b| b == b'\t' || (32..=126).contains(&b))
    {
        return Err("invalid SIP reason phrase".into());
    }
    let code: u16 = code.parse().map_err(|_| "invalid SIP status code")?;
    if !(100..700).contains(&code) {
        return Err("invalid SIP status code".into());
    }
    let mut headers = std::collections::BTreeMap::new();
    for line in lines {
        if headers.len() >= 64 {
            return Err("too many SIP headers".into());
        }
        let (name, value) = line.split_once(':').ok_or("malformed SIP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err("invalid SIP header".into());
        }
        let name = match name.to_ascii_lowercase().as_str() {
            "v" => "via".into(),
            "i" => "call-id".into(),
            "l" => "content-length".into(),
            other => other.to_owned(),
        };
        if ["via", "call-id", "cseq", "content-length"].contains(&name.as_str())
            && headers.contains_key(&name)
        {
            return Err("ambiguous SIP transaction header".into());
        }
        headers.insert(name, value.trim());
    }
    let cseq = headers
        .get("cseq")
        .ok_or("missing SIP CSeq")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if cseq.len() != 2
        || cseq[0].parse::<u32>().ok() != Some(sequence)
        || cseq[1] != method
        || headers.get("call-id").copied() != Some(call_id)
    {
        return Err("SIP transaction mismatch".into());
    }
    let via = headers.get("via").ok_or("missing SIP Via")?;
    let branches = via
        .split(';')
        .filter_map(|v| v.trim().strip_prefix("branch="))
        .collect::<Vec<_>>();
    if branches != [branch] {
        return Err("SIP branch mismatch or ambiguity".into());
    }
    let body_bytes = if let Some(length) = headers.get("content-length") {
        let length = length
            .parse::<usize>()
            .map_err(|_| "invalid SIP Content-Length")?;
        if length > 2048 || (bytes.len() > end + 4 && bytes.len() - end - 4 != length) {
            return Err("invalid SIP body framing".into());
        }
        Some(length)
    } else {
        None
    };
    Ok(ResponseHead {
        status: code,
        header_bytes: end + 4,
        body_bytes,
    })
}

pub fn response_head(
    bytes: &[u8],
    call_id: &str,
    branch: &str,
    method: &str,
    sequence: u32,
) -> Result<u16, String> {
    Ok(parse_response_head(bytes, call_id, branch, method, sequence)?.status)
}

pub fn response_datagram(
    bytes: &[u8],
    call_id: &str,
    branch: &str,
    method: &str,
    sequence: u32,
) -> Result<u16, String> {
    let head = parse_response_head(bytes, call_id, branch, method, sequence)?;
    let actual = bytes.len() - head.header_bytes;
    if actual > 2048 || head.body_bytes.is_some_and(|expected| expected != actual) {
        return Err("incomplete or excess SIP datagram body".into());
    }
    Ok(head.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sip_transactions_reject_duplicate_headers_and_branch_confusion() {
        let valid="SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKtest\r\nCall-ID: fixture\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            response_head(valid.as_bytes(), "fixture", "z9hG4bKtest", "OPTIONS", 1).unwrap(),
            200
        );
        for invalid in [
            valid.replace("CSeq: 1 OPTIONS", "CSeq: 1 OPTIONS\r\nCSeq: 2 INVITE"),
            valid.replace("CSeq: 1 OPTIONS", "CSeq: invalid OPTIONS"),
            valid.replace("branch=z9hG4bKtest", "branch=other;branch=z9hG4bKtest"),
            valid.replace("200 OK", "200 OK\nInjected: yes"),
            valid.replace("Content-Length: 0", "Content-Length: invalid"),
        ] {
            assert!(
                response_head(invalid.as_bytes(), "fixture", "z9hG4bKtest", "OPTIONS", 1).is_err()
            );
        }
        assert!(response_head(valid.as_bytes(), "other", "z9hG4bKtest", "OPTIONS", 1).is_err());
        let missing_body = valid.replace("Content-Length: 0", "Content-Length: 4");
        assert!(response_datagram(
            missing_body.as_bytes(),
            "fixture",
            "z9hG4bKtest",
            "OPTIONS",
            1
        )
        .is_err());
        assert_eq!(
            response_datagram(
                format!("{missing_body}test").as_bytes(),
                "fixture",
                "z9hG4bKtest",
                "OPTIONS",
                1
            )
            .unwrap(),
            200
        );
    }
}
