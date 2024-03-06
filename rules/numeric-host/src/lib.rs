use anyhow::{anyhow, Ok};
use bulwark_wasm_sdk::*;
use lazy_static::lazy_static;
use regex::Regex;

struct NumericHostPlugin;

fn check_numeric_host(req: Request) -> std::result::Result<bool, anyhow::Error> {
    let host = req
        .headers()
        .get("Host")
        .ok_or(anyhow!("Missing Host Header."))?;

    lazy_static! {
        static ref NUMERIC_HOST_REGEX: Regex =
        Regex::new(r"^((?:(?:[0-9]+|0(x|X)[0-9a-fA-F]+|0(b|B)[0-7]+)\.){0,3}(?:[0-9]+|0(x|X)[0-9a-fA-F]+|0(b|B)[0-7]+)|\[[0-9a-fA-F:]+\])(:[0-9]{1,5})?$")
            .unwrap();
    }
    let match_invalid_host = NUMERIC_HOST_REGEX.find(host.to_str()?);
    Ok(match_invalid_host.is_some())
}

#[bulwark_plugin]
impl Handlers for NumericHostPlugin {
    fn on_request_decision() -> Result {
        if check_numeric_host(get_request())? {
            set_restricted(1.0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_numeric_host() -> Result {
        let test_cases = [
            ("www.bulwark.security", false),
            ("www.bulwark.security:80", false),
            ("www.bul-wark.security:80", false),
            ("www.bul-wark.123", false),
            ("www.bul-wark98987.security:80", false),
            ("0xwww.bul-wark98987.security:80", false),
            // IPv4
            ("127.0.0.1", true),
            ("127.0.0.1:80", true),
            ("192.168.1.1", true),
            ("192.168.1.255", true),
            ("255.255.255.255", true),
            ("0.0.0.0", true),
            ("127.1", true),
            ("192.168.1.256", true),
            ("0x8.0X8.010.8", true),
            ("0x1.0x1.0x1.0x1", true),
            // IPv6
            ("[1:2:3:4:5:6:7:8]", true),
            ("[1:2:3:4:5:6:7:8]:80", true),
            ("[1::]", true),
            ("[1:2:3:4:5:6:7::]", true),
            ("[1::8]", true),
            ("[1:2:3:4:5:6::8]", true),
            ("[1:2:3:4:5:::8]", true),
            ("[1::7:8]", true),
            ("[1:2:3:4:5::7:8]", true),
            ("[1:2:3:4:5::8]", true),
            ("[1::6:7:8]", true),
            ("[1:2:3:4::6:7:8]", true),
            ("[1:2:3:4::8]", true),
            ("[1::5:6:7:8]", true),
            ("[1:2:3::5:6:7:8]", true),
            ("[1:2:3::8]", true),
            ("[1::4:5:6:7:8]", true),
            ("[1:2::4:5:6:7:8]", true),
            ("[1:2::8]", true),
            ("[1::3:4:5:6:7:8]", true),
            ("[::2:3:4:5:6:7:8]", true),
            ("[::8]", true),
            ("[::]", true),
            ("[::]:443", true),
            // numerals
            ("2147483647", true),
            ("0", true),
            ("909090:8080", true),
            ("0x989890fa", true),
            ("0x989890fa:8080", true),
            ("0b1010101010", true),
            ("0B1010101010", true),
            ("0b1010101010:8080", true),
            ("0651626", true),
            ("0651626:8080", true),
        ];

        for (host, expected) in test_cases {
            let builder = http::Request::builder();
            let req = builder
                .header("Host", http::HeaderValue::from_static(host))
                .body(BodyChunk {
                    received: true,
                    end_of_stream: true,
                    size: 0,
                    start: 0,
                    content: vec![],
                })
                .unwrap();
            let actual = check_numeric_host(req)?;
            assert_eq!(actual, expected);
        }

        Ok(())
    }
}
