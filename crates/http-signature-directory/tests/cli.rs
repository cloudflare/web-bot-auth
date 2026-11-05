use std::process::Command;

#[test]
fn invalid_urls_report_structured_failures() {
    for url in [
        "not a URL",
        "http://example.com/",
        "https://user@example.com/",
        "https://user:password@example.com/",
        "https://example.com/#fragment",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_http-signature-directory"))
            .arg(url)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        // main's Result termination appends an Error line after the JSON.
        let mut results =
            serde_json::Deserializer::from_slice(&output.stderr).into_iter::<serde_json::Value>();
        let result = results.next().unwrap().unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["details"]["url"], url);
        assert_eq!(result["details"]["keys_count"], 0);
        assert!(result["details"]["errors"][0].is_string());
    }
}
