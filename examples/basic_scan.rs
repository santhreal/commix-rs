use commix_rs::Commix;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable tracing logs to see what commix is doing in the background
    tracing_subscriber::fmt::init();

    println!("Starting Commix deep audit scan...");

    // 1. One-Liner Default Scan
    // This connects to the target with default settings (batch mode enabled)
    // let result = Commix::scan_url("http://example.com/api?id=1").await?;

    // 2. Advanced Builder Scan
    // Useful for authenticated targets, evasion, and precise targeting.
    let scanner = Commix::builder()
        .url("http://localhost:8080/vulnerable_endpoint?q=test")
        .method("GET")
        .level(3)
        .auth_bearer("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        .tamper_script("space2hash")
        .ignore_waf(true)
        .batch(true)
        .build();

    // The scan runs completely asynchronously without hanging the main thread
    match scanner.scan().await {
        Ok(result) => {
            if result.is_vulnerable() {
                // The Display implementation will nicely format all output
                println!("\n🚨 {}", result);
            } else {
                println!("\n✅ Target appears secure against command injection.");
            }
        }
        Err(e) => {
            eprintln!("\n❌ Command Injection scanning failed: {}", e);
        }
    }

    Ok(())
}
