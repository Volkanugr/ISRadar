//! Dedicated-endpoint policy probes. REGISTER is a binding query (no Contact).
//! INVITE requires an unsupported validation extension and immediately cleans up any unexpected dialog.
use crate::{
    results::{Observation, Outcome},
    vectors::{registry::Backend, TestContext},
};
use anyhow::{ensure, Context, Result};
use tokio::net::UdpSocket;

fn header<'a>(message: &'a str, name: &str) -> Option<&'a str> {
    message
        .split("\r\n")
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

async fn send(socket: &UdpSocket, message: &str, context: &TestContext) -> Result<()> {
    ensure!(
        message.len() <= 2048,
        "SIP request exceeds policy probe cap"
    );
    let sent = socket.send(message.as_bytes()).await?;
    ensure!(sent == message.len(), "partial SIP request");
    context.counters.sent(sent);
    Ok(())
}

pub(crate) async fn execute(backend: Backend, context: &TestContext) -> Result<Observation> {
    backend.validate_options(&context.protocol)?;
    let target = context.target.as_ref().context("SIP target required")?;
    let settings = context
        .protocol
        .sip
        .as_ref()
        .context("configured SIP settings required")?;
    let socket = UdpSocket::bind(if target.ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target.address()).await?;
    let local = socket.local_addr()?;
    let authority = target.address().to_string();
    let uri = format!("sip:{}@{authority}", settings.test_user);
    let from = format!("<{uri}>;tag={:016x}", rand::random::<u64>());
    let original_to = format!("<{uri}>");
    let call_id = format!("{:016x}@isradar.invalid", rand::random::<u64>());
    let branch = format!("z9hG4bK{:016x}", rand::random::<u64>());
    let request = |method: &str, sequence: u32, to: &str, via: &str, extra: &str| {
        format!("{method} {} SIP/2.0\r\nVia: SIP/2.0/UDP {local};branch={via};rport\r\nMax-Forwards: 0\r\nFrom: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {sequence} {method}\r\n{extra}Content-Length: 0\r\n\r\n",if method=="REGISTER"{format!("sip:{authority}")}else{uri.clone()})
    };
    let method = if backend == Backend::SipInvite {
        "INVITE"
    } else {
        "REGISTER"
    };
    let extra = if backend == Backend::SipInvite {
        "Require: isradar-no-session\r\nExpires: 0\r\n"
    } else {
        ""
    };
    send(
        &socket,
        &request(method, 1, &original_to, &branch, extra),
        context,
    )
    .await?;
    let mut canceled = false;
    let mut final_response = None;
    let mut buffer = [0u8; 4096];
    for _ in 0..8 {
        let size = socket.recv(&mut buffer).await?;
        context.counters.received(size);
        let text = std::str::from_utf8(&buffer[..size])?;
        if header(text, "CSeq") == Some("1 CANCEL") {
            crate::vectors::protocols::sip_response_for(
                &buffer[..size],
                &call_id,
                &branch,
                "CANCEL",
                1,
            )?;
            continue;
        }
        let code = crate::vectors::protocols::sip_response_for(
            &buffer[..size],
            &call_id,
            &branch,
            method,
            1,
        )?;
        if code < 200 {
            if backend == Backend::SipInvite && !canceled {
                send(
                    &socket,
                    &request("CANCEL", 1, &original_to, &branch, ""),
                    context,
                )
                .await?;
                canceled = true;
            }
            continue;
        }
        let to = header(text, "To").unwrap_or(&original_to).to_owned();
        ensure!(
            to.len() <= 512 && to.bytes().all(|b| (32..=126).contains(&b)),
            "invalid SIP To value"
        );
        final_response = Some((code, to));
        break;
    }
    let (code, to) =
        final_response.context("SIP final response was not received within the response cap")?;
    if backend == Backend::SipInvite {
        let ack_branch = if code < 300 {
            format!("z9hG4bK{:016x}", rand::random::<u64>())
        } else {
            branch.clone()
        };
        send(&socket, &request("ACK", 1, &to, &ack_branch, ""), context).await?;
        if code < 300 {
            // Never follow Contact/Record-Route to another host. All cleanup stays on the configured socket peer.
            let bye_branch = format!("z9hG4bK{:016x}", rand::random::<u64>());
            send(&socket, &request("BYE", 2, &to, &bye_branch, ""), context).await?;
            let mut cleaned = false;
            for _ in 0..4 {
                let size = socket.recv(&mut buffer).await?;
                context.counters.received(size);
                let text = std::str::from_utf8(&buffer[..size])?;
                if header(text, "CSeq") != Some("2 BYE") {
                    continue;
                }
                let result = crate::vectors::protocols::sip_response_for(
                    &buffer[..size],
                    &call_id,
                    &bye_branch,
                    "BYE",
                    2,
                )?;
                ensure!(
                    (200..300).contains(&result),
                    "unexpected SIP dialog cleanup was rejected"
                );
                cleaned = true;
                break;
            }
            ensure!(
                cleaned,
                "unexpected SIP dialog cleanup was not acknowledged"
            );
        }
    }
    let mut value=Observation::success(format!("SIP {method} policy response {code}; no Contact followed, no registration changed, no media sent"));
    value.response_received = true;
    value
        .protocol_details
        .insert("sip_method".into(), method.into());
    value
        .protocol_details
        .insert("sip_status".into(), code.into());
    value
        .protocol_details
        .insert("cancel_sent".into(), canceled.into());
    if settings
        .expected_status
        .is_some_and(|expected| code != expected)
        || (settings.expected_status.is_none() && code >= 300)
    {
        value.outcome = Outcome::RemoteRejection;
    }
    Ok(value)
}
