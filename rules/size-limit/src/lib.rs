use bulwark_wasm_sdk::*;

/// A soft limit will be applied to requests above 15 MiB
const DEFAULT_SOFT_LIMIT: u64 = 15 * 1048576;

/// Maximum acceptable request body length is 50 MiB
const DEFAULT_HARD_LIMIT: u64 = 50 * 1048576;

// This generally will not result in a restrict decision in isolation
const DEFAULT_SOFT_WEIGHT: f64 = 0.15;

// Hitting the hard limit will give maximum block weight
const DEFAULT_HARD_WEIGHT: f64 = 1.0;

#[derive(Debug, PartialEq, Eq)]
enum BodyLimit {
    Normal,
    SoftLimit,
    HardLimit,
}

/// Checks if the request is above either the hard or soft limit
fn body_limit(soft_limit: Option<Value>, hard_limit: Option<Value>, size: u64) -> BodyLimit {
    let soft_limit = soft_limit
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_SOFT_LIMIT);
    let hard_limit = hard_limit
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_HARD_LIMIT);
    match size {
        x if x > hard_limit => BodyLimit::HardLimit,
        x if x > soft_limit => BodyLimit::SoftLimit,
        _ => BodyLimit::Normal,
    }
}

/// Determine the restrict weight based on the body limit
fn weight_limit(soft_weight: Option<Value>, hard_weight: Option<Value>, limit: BodyLimit) -> f64 {
    match limit {
        BodyLimit::HardLimit => hard_weight
            .and_then(|value| value.as_f64())
            .unwrap_or(DEFAULT_HARD_WEIGHT),

        BodyLimit::SoftLimit => soft_weight
            .and_then(|value| value.as_f64())
            .unwrap_or(DEFAULT_SOFT_WEIGHT),
        BodyLimit::Normal => 0.0,
    }
}

struct SizeLimitPlugin;

#[bulwark_plugin]
impl Handlers for SizeLimitPlugin {
    fn on_request_decision() -> Result {
        let request = get_request();
        let content_length = request
            .headers()
            .get("Content-Length")
            .and_then(|hv| hv.to_str().ok())
            .and_then(|hv| hv.parse().ok());
        if let Some(content_length) = content_length {
            let weight = weight_limit(
                get_config_value("soft_weight"),
                get_config_value("hard_weight"),
                body_limit(
                    get_config_value("soft_limit"),
                    get_config_value("hard_limit"),
                    content_length,
                ),
            );
            set_restricted(weight);
        }
        Ok(())
    }

    fn on_request_body_decision() -> Result {
        let request = get_request();
        let weight = weight_limit(
            get_config_value("soft_weight"),
            get_config_value("hard_weight"),
            body_limit(
                get_config_value("soft_limit"),
                get_config_value("hard_limit"),
                request.body().size,
            ),
        );
        set_restricted(weight);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_limit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let test_cases = [
            (
                // This request has no body
                None,
                None,
                0,
                BodyLimit::Normal,
            ),
            (
                // This request has a body that is exactly at the soft limit
                None,
                None,
                DEFAULT_SOFT_LIMIT,
                BodyLimit::Normal,
            ),
            (
                // This request has a body that is exactly at the hard limit
                None,
                None,
                DEFAULT_HARD_LIMIT,
                BodyLimit::SoftLimit,
            ),
            (
                // This request has a body above the upper limit
                None,
                None,
                DEFAULT_HARD_LIMIT + 1,
                BodyLimit::HardLimit,
            ),
            (
                // This request has no body
                Some(value!(5)),
                Some(value!(10)),
                0,
                BodyLimit::Normal,
            ),
            (
                // This request has a body that is exactly at the soft limit
                Some(value!(5)),
                Some(value!(10)),
                5,
                BodyLimit::Normal,
            ),
            (
                // This request has a body that is exactly at the hard limit
                Some(value!(5)),
                Some(value!(10)),
                10,
                BodyLimit::SoftLimit,
            ),
            (
                // This request has a body above the upper limit
                Some(value!(5)),
                Some(value!(10)),
                11,
                BodyLimit::HardLimit,
            ),
        ];

        for (soft_limit, hard_limit, size, expected) in test_cases {
            let limit = body_limit(soft_limit, hard_limit, size);
            assert_eq!(limit, expected);
        }

        Ok(())
    }
}
