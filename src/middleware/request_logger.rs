#[cfg(feature = "tui-support")]
use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
    body::Body,
};
#[cfg(feature = "tui-support")]
use std::sync::Arc;
#[cfg(feature = "tui-support")]
use crate::ServerStats;

#[cfg(feature = "tui-support")]
use std::time::{Instant, Duration}; // ✅ Use standard Instant & Duration

#[cfg(feature = "tui-support")]
pub async fn track_requests(
    State(stats): State<Arc<ServerStats>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let request_info = format!("{} {}", req.method(), req.uri());

    // Log the request properly
    stats.increment_request(request_info.clone(), Duration::from_millis(0)).await;


    let start = Instant::now();
    let response = next.run(req).await;
    let status = response.status();

    // ✅ Store timestamps for calculating RPS using std::Instant
    {
        let now = Instant::now();
        let mut times = stats.request_times.lock().await;

        times.push(now); // ✅ Now correctly uses std::Instant

        // ✅ Keep only requests from the last 1 second (Fixes blank RPS)
        times.retain(|&t| now.duration_since(t) < Duration::from_secs(1));
    }

    // Log errors separately
    if status.is_client_error() || status.is_server_error() {
        stats.increment_error(format!("{} - {}", status, request_info)).await;
    }

    Ok(response)
}
