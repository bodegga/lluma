//! RFC 9292 Binary HTTP framing of the inner request/response (Fable ruling R4:
//! use BHTTP, don't invent an inner wire format). `lluma-net` encodes the
//! request and decodes the response; the gateway does the mirror (decode
//! request, encode response). Known-length, single message.

use std::io::Cursor;

use bhttp::{Message, Mode};

use crate::error::NetError;

/// An inner HTTP request to be sealed to the gateway. `authority` is deliberately
/// omitted — the gateway overwrites it with its configured origin (SSRF guard).
#[derive(Debug, Clone)]
pub struct InnerRequest {
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// The inner HTTP response recovered from the sealed OHTTP response.
#[derive(Debug, Clone)]
pub struct InnerResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Encode an `InnerRequest` as a known-length BHTTP request message.
pub(crate) fn encode_request(r: &InnerRequest) -> Result<Vec<u8>, NetError> {
    let mut msg = Message::request(
        r.method.clone().into_bytes(),
        b"https".to_vec(),
        Vec::new(),
        r.path.clone().into_bytes(),
    );
    if let Some(ct) = &r.content_type {
        msg.put_header(b"content-type".to_vec(), ct.clone().into_bytes());
    }
    msg.write_content(&r.body);
    let mut out = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut out)
        .map_err(|_| NetError::Bhttp)?;
    Ok(out)
}

/// Decode a BHTTP response message into `{status, body}`.
pub(crate) fn decode_response(bytes: &[u8]) -> Result<InnerResponse, NetError> {
    let mut cur = Cursor::new(bytes);
    let msg = Message::read_bhttp(&mut cur).map_err(|_| NetError::Bhttp)?;
    let status = u16::from(msg.control().status().ok_or(NetError::Bhttp)?);
    Ok(InnerResponse {
        status,
        body: msg.content().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A BHTTP request encoded by `lluma-net` must round-trip through a decode
    // that mirrors the gateway side (proves the two ends agree on framing).
    #[test]
    fn request_round_trips() {
        let req = InnerRequest {
            method: "POST".into(),
            path: "/v1/issue".into(),
            content_type: Some("application/json".into()),
            body: b"{\"hello\":1}".to_vec(),
        };
        let bytes = encode_request(&req).expect("encode");
        let mut cur = Cursor::new(&bytes[..]);
        let msg = Message::read_bhttp(&mut cur).expect("decode");
        assert_eq!(msg.content(), req.body.as_slice());
    }

    #[test]
    fn response_round_trips() {
        let mut msg = Message::response(bhttp::StatusCode::try_from(200u16).unwrap());
        msg.write_content(b"ok-body");
        let mut buf = Vec::new();
        msg.write_bhttp(Mode::KnownLength, &mut buf).expect("encode resp");
        let got = decode_response(&buf).expect("decode resp");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"ok-body");
    }
}
