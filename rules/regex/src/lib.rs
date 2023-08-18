use anyhow::anyhow;
use bulwark_wasm_sdk::*;
use regex::RegexSetBuilder;

struct RegexPlugin;

fn get_sources(value: Option<Value>, request: Request) -> std::result::Result<Vec<Vec<u8>>, Error> {
    let value = value.unwrap_or_else(|| Value::String(String::from("all")));
    let mut sources = vec![];
    match value {
        Value::String(keyword) => {
            if &keyword == "all" {
                if let Some(host) = request.uri().host() {
                    sources.push(host.as_bytes().to_vec())
                }
                sources.push(request.uri().path().as_bytes().to_vec());
                if let Some(query) = request.uri().query() {
                    sources.push(query.as_bytes().to_vec());
                }
                for (_, header_value) in request.headers() {
                    sources.push(header_value.as_bytes().to_vec());
                }
                if request.body().received {
                    sources.push(request.body().content.clone());
                }
                Ok(sources)
            } else {
                Err(anyhow!("invalid location config"))
            }
        }
        Value::Object(locations) => {
            for (key, value) in locations {
                match key.as_str() {
                    "host" => {
                        if let Some(host) = request.uri().host() {
                            sources.push(host.as_bytes().to_vec())
                        }
                    }
                    "path" => sources.push(request.uri().path().as_bytes().to_vec()),
                    "query" => {
                        if let Some(query) = request.uri().query() {
                            sources.push(query.as_bytes().to_vec())
                        }
                    }
                    "header" => {
                        if let Some(headers) = value.as_array() {
                            for header in headers {
                                if let Some(header_name) = header.as_str() {
                                    if let Some(header_value) = request.headers().get(header_name) {
                                        sources.push(header_value.as_bytes().to_vec());
                                    }
                                }
                            }
                        }
                    }
                    "body" => {
                        if request.body().received {
                            sources.push(request.body().content.clone());
                        }
                    }
                    _ => {
                        eprintln!("invalid location type: {}", key);
                        append_tags(["error"]);
                    }
                }
            }
            Ok(sources)
        }
        _ => Err(anyhow!("invalid location config")),
    }
}

fn get_patterns(value: Option<Value>) -> std::result::Result<Vec<String>, Error> {
    let value = value.ok_or(anyhow!("missing patterns config"))?;
    let pattern_values = value.as_array().ok_or(anyhow!("invalid patterns config"))?;
    let mut patterns = Vec::with_capacity(pattern_values.len());
    for value in pattern_values {
        let pattern = value.as_str().ok_or(anyhow!("pattern was not string"))?;
        patterns.push(pattern.to_string());
    }
    Ok(patterns)
}

#[inline(always)]
fn regex_handler() -> Result {
    let sources = get_sources(get_config_value("location"), get_request())?;
    let patterns = get_patterns(get_config_value("patterns"))?;
    let regex_set = RegexSetBuilder::new(patterns).build()?;
    let mut match_count = 0;
    for source in sources {
        if let Ok(haystack) = std::str::from_utf8(source.as_slice()) {
            let matches = regex_set.matches(haystack);
            if matches.matched_any() {
                match_count += matches.iter().count();
            }
        }
    }
    if match_count > 0 {
        if let Some(restrict_increment) = get_config_value("restrict") {
            let restrict_increment = restrict_increment
                .as_f64()
                .ok_or(anyhow!("restrict must be f64"))?;
            set_restricted(restrict_increment * match_count as f64)
        } else if let Some(accept_increment) = get_config_value("accept") {
            let accept_increment = accept_increment
                .as_f64()
                .ok_or(anyhow!("accept must be f64"))?;
            set_restricted(accept_increment * match_count as f64)
        } else {
            return Err(anyhow!("no accept or restrict increment specified"));
        }
    }
    Ok(())
}

#[bulwark_plugin]
impl Handlers for RegexPlugin {
    fn on_request_decision() -> Result {
        regex_handler()
    }

    fn on_request_body_decision() -> Result {
        regex_handler()
    }
}
