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
    let path = req.uri().path();
    let method = req.method();
    let request_info = format!("{} {}", method, path);
    
    // Check if this is a notification-related request
    let is_notification_request = path.contains("/notifications") || 
                                 path.contains("/notification");
    
    // Only increment visible requests if it's not notification-related
    if !is_notification_request {
        stats.increment_request(request_info.clone(), Duration::from_millis(0)).await;
    }
    
    // Track timing for all requests
    let start = Instant::now();
    let response = next.run(req).await;
    let status = response.status();
    let duration = start.elapsed();
    
    // Store timestamps for calculating RPS using std::Instant for all requests
    {
        let now = Instant::now();
        let mut times = stats.request_times.lock().await;
        times.push(now);
        // Keep only requests from the last 1 second (Fixes blank RPS)
        times.retain(|&t| now.duration_since(t) < Duration::from_secs(1));
    }
    
    // Update response times regardless of request type
    {
        let mut latencies = stats.response_times.lock().await;
        if latencies.len() > 100 { latencies.remove(0); }
        latencies.push(duration);
    }
    
    // For notification requests, still increment the counter but don't add to visible list
    if is_notification_request {
        let mut count = stats.request_count.borrow().clone();
        count += 1;
        let _ = stats.request_count.send(count);
    }
    
    // Log errors separately (for all request types)
    if status.is_client_error() || status.is_server_error() {
        stats.increment_error(format!("{} - {}", status, request_info)).await;
    }
    
    Ok(response)
}
