use anyhow::{anyhow, Ok};
use bulwark_wasm_sdk::*;
use regex::*;

struct NumericHostPlugin;

fn check_numeric_host(req: Request) -> std::result::Result<bool, anyhow::Error> {
    let host = req
        .headers()
        .get("Host")
        .ok_or(anyhow!("Missing Host Header."))?;

    let re_ipv4 = Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(:[0-9]{1,5})?$").unwrap();
    let re_ipv6 = Regex::new(r"\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}\](:[0-9]{1,5})?|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))").unwrap();
    // numerals as IPv4
    let re_decimal = Regex::new(r"^[0-9]{1,10}(:[0-9]{1,5})?$").unwrap();
    let re_binary = Regex::new(r"^0[bB][0-1]{1,32}(:[0-9]{1,5})?$").unwrap();
    let re_hex = Regex::new(r"^0[xX][0-9a-fA-F]{1,8}(:[0-9]{1,5})?$").unwrap();
    let re_octal = Regex::new(r"^0[0-7]{1,11}(:[0-9]{1,5})?$").unwrap();

    let match_ipv4 = re_ipv4.find(host.to_str()?);
    let match_ipv6 = re_ipv6.find(host.to_str()?);
    let match_decimal = re_decimal.find(host.to_str()?);
    let match_binary = re_binary.find(host.to_str()?);
    let match_hex = re_hex.find(host.to_str()?);
    let match_octal = re_octal.find(host.to_str()?);

    match (
        match_ipv4,
        match_ipv6,
        match_decimal,
        match_binary,
        match_hex,
        match_octal,
    ) {
        (None, None, None, None, None, None) => Ok(false),
        _ => Ok(true),
    }
}

#[bulwark_plugin]
impl Handlers for NumericHostPlugin {
    fn on_request_decision() -> Result {
        if check_numeric_host(get_request())? {
            set_restricted(1.0);
        }
        Ok(())
    }

    fn on_request_body_decision() -> Result {
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
            // IPv4
            ("127.0.0.1", true),
            ("127.0.0.1:80", true),
            ("192.168.1.1", true),
            ("192.168.1.255", true),
            ("255.255.255.255", true),
            ("0.0.0.0", true),
            ("3...3", false),
            ("30.168.1.255.1", false),
            ("127.1", false),
            ("192.168.1.256", false),
            ("-1.2.3.4", false),
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
            ("[fe80::7:8%eth0]", true),
            ("[fe80::7:8%1]", true),
            // numerals
            ("2147483647", true),
            ("0", true),
            ("909090:8080", true),
            ("0x989890fa", true),
            ("0X989890fa", true),
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
