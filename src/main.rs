#![allow(dead_code, unused)]
use api::graphql::graphql_handler;
use async_graphql::Request;
use axum::routing::post;
use axum::Extension;
use axum::{routing::get, Router};
use axum::middleware::{from_fn, from_fn_with_state};
use db::queries::contract::ContractDoc;
use db::queries::taskorder::TaskOrderDoc;
use db::queries::team::TeamDoc;
use db::queries::user::UserDoc;
use crate::db::queries::product::{ProductDoc, ProductTypeDoc};
use crate::db::queries::review::ReviewDoc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{broadcast, watch};
use tower_http::cors::CorsLayer;
use std::net::SocketAddr;
use dotenvy::dotenv;
use utoipa_swagger_ui::SwaggerUi;
use utoipa_rapidoc::RapiDoc;
use utoipa::OpenApi;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use moka::sync::Cache;
use tracing_subscriber;
use crate::db::queries::requests::RequestDoc;

#[cfg(feature = "tui-support")]
use sysinfo::System; // Only CPU and memory will be used

#[cfg(feature = "tui-support")]
use crate::middleware::request_logger::track_requests;

#[cfg(feature = "tui-support")]
use ratatui::{prelude::*, widgets::*};

#[cfg(feature = "tui-support")]
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{enable_raw_mode, disable_raw_mode},
};

mod config;
mod db;
mod api;
mod middleware;
mod utils;
mod graphql;

use crate::config::Config;
use crate::middleware::auth::{jwt_middleware, rbac_middleware, create_permission_cache};
use crate::api::auth::AuthDoc;
use crate::api::google_oauth::GoogleOAuthDoc;
use crate::graphql::graph_schema::{create_schema, AppSchema};
use crate::api::graphql::graphql_routes;
//
// ServerStats: Extended metrics for the TUI dashboard (compiled with tui-support)
//



#[cfg(feature = "tui-support")]
struct ServerStats {
    request_count: watch::Sender<u64>,
    request_rx: watch::Receiver<u64>,
    error_count: AtomicU64,
    request_times: tokio::sync::Mutex<Vec<Instant>>, // ✅ Now using std::time::Instant
    last_requests: tokio::sync::Mutex<Vec<String>>,
    last_errors: tokio::sync::Mutex<Vec<String>>,
    response_times: tokio::sync::Mutex<Vec<Duration>>,
}


#[cfg(feature = "tui-support")]
impl ServerStats {
    fn new() -> Arc<Self> {
        let (tx, rx) = watch::channel(0);
        Arc::new(Self {
            request_count: tx,
            request_rx: rx,
            error_count: AtomicU64::new(0),
            request_times: tokio::sync::Mutex::new(vec![]),
            last_requests: tokio::sync::Mutex::new(vec![]),
            last_errors: tokio::sync::Mutex::new(vec![]),
            response_times: tokio::sync::Mutex::new(vec![]),
        })
    }

    /// Call this on every API request.
    async fn increment_request(&self, request: String, latency: Duration) {
        let mut count = self.request_count.borrow().clone();
        count += 1;
        let _ = self.request_count.send(count);

        let now = Instant::now();
        {
            let mut times = self.request_times.lock().await;
            times.push(now);
            times.retain(|&t| now.duration_since(t) < Duration::from_secs(1));
        }
        {
            let mut logs = self.last_requests.lock().await;
            logs.push(request);
            if logs.len() > 10 {
                logs.remove(0);
            }
        }
        {
            let mut latencies = self.response_times.lock().await;  // ✅ Fix: Use .await here
            if latencies.len() > 100 { latencies.remove(0); }  // Keep last 100 latencies
            latencies.push(latency);
        }
    }



    /// Call this on error responses.
    async fn increment_error(&self, error: String) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
        let mut errors = self.last_errors.lock().await;
        errors.push(error);
        if errors.len() > 10 {
            errors.remove(0);
        }
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.request_rx.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    Config::init();

    std::fs::create_dir_all("logs").expect("Failed to create logs directory");

    //let file_appender = tracing_appender::rolling::daily("logs", "app.log");
    //let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    //tracing_subscriber::fmt()
    //    .with_max_level(tracing::Level::INFO) // Adjust log level as needed (e.g., DEBUG, TRACE)
    //    .with_target(true) // Include target (module path) in logs
    //    .with_writer(non_blocking) // Write logs to the file
    //   .init();

    let permission_cache = create_permission_cache();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(2)
        .idle_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let merged_doc = AuthDoc::openapi()
        .merge_from(GoogleOAuthDoc::openapi())
        .merge_from(ProductTypeDoc::openapi())
        .merge_from(ProductDoc::openapi())
        .merge_from(ReviewDoc::openapi())
        .merge_from(ContractDoc::openapi())
        .merge_from(TeamDoc::openapi())
        .merge_from(UserDoc::openapi())
        .merge_from(TaskOrderDoc::openapi())
        .merge_from(RequestDoc::openapi());

    #[cfg(feature = "tui-support")]
    let stats = ServerStats::new();
    let graphql_schema = create_schema(pool.clone());

    // Public route, both GET and POST methods on /graphql
    // GraphQL Playground route (no JWT required)
   
    // Public routes (including Playground)
    let public_routes = Router::new()
    .merge(api::auth::auth_routes())
    .merge(api::google_oauth::g_auth_routes());

    // Private routes
    let private_routes = Router::new()
    .merge(api::product::product_routes())
    .merge(api::contract::contract_routes())
    .merge(api::review::review_routes())
    .merge(api::team::team_routes())
    .merge(api::taskorder::taskorder_routes())
    .merge(api::auth::secure_auth_routes())
    .merge(api::wfs::wfs_routes())
    .merge(api::user::user_routes())
    .merge(api::requests::request_routes())
    .merge(graphql_routes(graphql_schema)) // secured POST route
    .route_layer(from_fn_with_state(pool.clone(), rbac_middleware))
    .route_layer(from_fn(jwt_middleware));

    let app = Router::new()
        .merge(api::health::health_routes())
        .merge(public_routes)
        .merge(private_routes)
        .merge(
            SwaggerUi::new("/swagger")
                .url("/api-docs/openapi.json", merged_doc.clone())
        )
        .merge(
            RapiDoc::with_openapi("/api-docs/rapidoc.json", merged_doc)
                .path("/rapidoc")
        )
        .layer(CorsLayer::permissive())
        .layer(Extension(permission_cache.clone()))
        .with_state(pool.clone());

    #[cfg(feature = "tui-support")]
    let app = app.route_layer(from_fn_with_state(stats.clone(), track_requests));

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let start_time = Instant::now();
    let is_running = Arc::new(AtomicBool::new(true));

    let server_task = tokio::spawn(run_server(
        app,
        shutdown_tx.clone(),
        pool.clone(),
        is_running.clone(),
    ));

    #[cfg(feature = "tui-support")]
    let tui_task = Some(tokio::spawn(run_tui(
        shutdown_tx.clone(),
        is_running.clone(),
        start_time,
        stats.clone(),
        pool.clone(),
    )));

    #[cfg(not(feature = "tui-support"))]
    let tui_task: Option<tokio::task::JoinHandle<()>> = None;


    tokio::select! {
        _ = server_task => println!("Server task finished."),
        _ = async {
            if let Some(t) = tui_task {
                t.await.ok();
            } else {
                shutdown_signal(shutdown_tx.subscribe(), pool.clone(), is_running.clone()).await;
            }
        } => (),
    }
    println!("Shutdown complete.");
}

async fn shutdown_signal(
    mut shutdown_rx: broadcast::Receiver<()>,
    pool: PgPool,
    is_running: Arc<AtomicBool>
) {
    tokio::select! {
        _ = signal::ctrl_c() => println!("Received Ctrl+C, shutting down..."),
        _ = shutdown_rx.recv() => println!("Received shutdown signal."),
    }
    println!("🛠️ Closing database pool...");
    pool.close().await;
    println!("✅ Database pool closed. Server shutting down.");
    is_running.store(false, Ordering::Relaxed);
}

async fn run_server(app: Router, shutdown_tx: broadcast::Sender<()>, pool: PgPool, is_running: Arc<AtomicBool>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running at http://{}", addr);

    let listener = TcpListener::bind(&addr).await.expect("Failed to bind listener");

    let shutdown_signal = shutdown_signal(shutdown_tx.subscribe(), pool.clone(), is_running.clone());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .expect("Server encountered an error");
}

#[cfg(feature = "tui-support")]
struct RequestSparkline {
    counts: [u64; 60],
    last_updated: Instant,
}

#[cfg(feature = "tui-support")]
impl RequestSparkline {
    fn new() -> Self {
        Self {
            counts: [0; 60],
            last_updated: Instant::now(),
        }
    }

    fn tick(&mut self, timestamps: &[Instant]) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_updated).as_secs();
    
        if elapsed > 0 {
            let shift = elapsed.min(60) as usize;
            self.counts.rotate_left(shift);
            for i in (60 - shift)..60 {
                self.counts[i] = 0;
            }
            self.last_updated += Duration::from_secs(elapsed);
        }
    
        // Count each timestamp only once into the right second bucket
        for &t in timestamps {
            let age = now.duration_since(t).as_secs();
            if age < 60 {
                let idx = 59 - age as usize;
                self.counts[idx] += 1;
            }
        }
    }
    
    

    fn average(&self) -> f64 {
        self.counts.iter().sum::<u64>() as f64 / 60.0
    }
    
    
    

    fn rps(&self) -> f64 {
        let sum: u64 = self.counts.iter().rev().take(5).sum();
        sum as f64 / 5.0
    }
    

    fn rpm(&self) -> u64 {
        self.counts.iter().sum()
    }

    fn sparkline_data(&self, width: usize) -> Vec<u64> {
        let clamped_width = width.clamp(1, 60);
        self.counts[60 - clamped_width..].to_vec()
    }
}


#[cfg(feature = "tui-support")]
async fn run_tui(
    shutdown_tx: broadcast::Sender<()>,
    is_running: Arc<AtomicBool>,
    start_time: Instant,
    stats: Arc<ServerStats>,
    pool: PgPool,
) {
    use crossterm::{execute, terminal::{Clear, ClearType}, cursor};
    use uuid::timestamp;
    use std::io::stdout;
    use ratatui::{
        widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline, BarChart},
        style::{Color, Style},
        layout::{Layout, Constraint, Direction},
    };
    use crossterm::event::{KeyEventKind};
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    enable_raw_mode().expect("Failed to enable raw mode");

    let mut stdout = stdout();
    execute!(stdout, Clear(ClearType::All), cursor::Hide)
        .expect("Failed to clear terminal and hide cursor");

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).expect("Failed to create terminal");

    let mut sys = System::new_all();
    let mut request_rx = stats.subscribe();

    let mut request_counts_per_second: Vec<u64> = vec![0; 60];  // Store last 60 seconds of request counts
    let mut cpu_usage_data: Vec<u64> = vec![0; 30];
    let mut request_sparkline = RequestSparkline::new();

    while is_running.load(Ordering::Relaxed) {
        sys.refresh_all();
        if event::poll(Duration::from_millis(50)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('Q') => {
                        shutdown_tx.send(()).unwrap();
                        is_running.store(false, Ordering::Relaxed);
                        break;
                    },
                    _ => {}
                }
            }
        }

        let cpu_usage = sys.global_cpu_usage() as u64;
        let memory_used = sys.used_memory() / 1024 / 1024;
        let memory_total = sys.total_memory() / 1024 / 1024;
        let uptime = Instant::now().duration_since(start_time);
        let uptime_str = format!(
            "{:02}:{:02}:{:02}",
            uptime.as_secs() / 3600,
            (uptime.as_secs() / 60) % 60,
            uptime.as_secs() % 60
        );

        let active_connections = pool.size()  - pool.num_idle() as u32;
        let idle_connections = pool.num_idle();
        let request_count = *request_rx.borrow();
        let error_count = stats.error_count.load(Ordering::Relaxed);

        let now = Instant::now();

        // Keep only the last 60 seconds of timestamps
        // Update request history
        let mut times = stats.request_times.lock().await;
        request_sparkline.tick(&times);
        times.clear(); // <-- ADD THIS!


        // Calculate metrics
        let rps = request_sparkline.rps();
        let rpm = request_sparkline.rpm();
        let avg_display_value = if rps >= 60.0 {
            request_sparkline.average()
        } else {
            rpm as f64
        };
        let display_label = if rps >= 60.0 { "RPS" } else { "RPM" };


        // Update CPU Sparkline Data
        cpu_usage_data.push(cpu_usage);
        if cpu_usage_data.len() > 30 {
            cpu_usage_data.remove(0);
        }

        // **PRECOMPUTE request and error logs BEFORE terminal.draw()**
        let recent_requests = {
            let requests = stats.last_requests.lock().await;
            requests.iter().map(|req| ListItem::new(req.clone())).collect::<Vec<_>>()
        };

        let recent_errors = {
            let errors = stats.last_errors.lock().await;
            errors.iter().map(|err| ListItem::new(err.clone())).collect::<Vec<_>>()
        };

        let mut latency_buckets: [u64; 10] = [0; 10]; // Buckets: 0-50ms, 50-100ms, ..., 450-500ms+
        {
            let times = stats.response_times.lock().await;
            for latency in times.iter() {
                let index = (latency.as_millis() / 50).min(9) as usize; // Each bucket is 50ms
                latency_buckets[index] += 1;
            }
        }

        let latency_labels = [
            "0-50ms", "51-100ms", "101-150ms", "151-200ms", "201-250ms",
            "251-300ms", "301-350ms", "351-400ms", "401-450ms", "450ms+"
        ];

        let latency_chart = BarChart::default()
            .block(Block::default().title("Request Latency Histogram").borders(Borders::ALL))
            .data(
                &latency_labels.iter()
                    .enumerate()
                    .map(|(i, &label)| (label, latency_buckets[i]))
                    .collect::<Vec<_>>()
            )
            .bar_width(8)
            .value_style(Style::default().fg(Color::Cyan));


        // Render Dashboard
        terminal.draw(|frame| {
            let size = frame.area();
        
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(20), // System & DB Info
                    Constraint::Percentage(40), // RPS/RPM, CPU, Latency
                    Constraint::Percentage(40), // API Requests & Errors
                ])
                .split(size);
        
            let top_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50), // System Info
                    Constraint::Percentage(50), // Database Info
                ])
                .split(layout[0]);
        
            let mid_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(34), // RPS/RPM Trend
                    Constraint::Percentage(33), // CPU Usage
                    Constraint::Percentage(33), // Latency Histogram
                ])
                .split(layout[1]);
        
            let bottom_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50), // API Requests
                    Constraint::Percentage(50), // Errors
                ])
                .split(layout[2]);
            
            // **System Info Block**
            let system_info = format!(
                "Uptime: {} | CPU: {:.2}% | Memory: {}/{} MB \nRequests: {} | Errors: {}",
                uptime_str, cpu_usage, memory_used, memory_total, request_count, error_count
            );
            let system_status = Paragraph::new(system_info)
                .block(Block::default().title("System Stats").borders(Borders::ALL));
        
            // **Database Connections Chart**
            let db_data = vec![
                ("Active", active_connections as u64),
                ("Idle", idle_connections as u64),
            ];
            let db_chart = BarChart::default()
                .block(Block::default().title("Database Connections").borders(Borders::ALL))
                .data(&db_data)
                .bar_width(8)
                .value_style(Style::default().fg(Color::Green));
        
            // **RPS/RPM Sparkline**
            let width = mid_row[1].width as usize;
            let sparkline_data = request_sparkline.sparkline_data(width);
            let max_y = *sparkline_data.iter().max().unwrap_or(&1);

            let rate_sparkline = Sparkline::default()
                .data(&sparkline_data)
                .block(Block::default().title(format!("{} Trend (Avg {:.2})", display_label, avg_display_value)).borders(Borders::ALL))
                .style(Style::default().fg(Color::Cyan))
                .max(max_y);

                    
            // **CPU Usage Sparkline**
            let cpu_sparkline = Sparkline::default()
                .data(&cpu_usage_data)
                .block(Block::default().title("CPU Usage (0-100%)").borders(Borders::ALL))
                .style(Style::default().fg(Color::Yellow))
                .max(100);
        
            // **Latency Histogram**
            let latency_chart = BarChart::default()
                .block(Block::default().title("Request Latency Histogram").borders(Borders::ALL))
                .data(
                    &latency_labels.iter()
                        .enumerate()
                        .map(|(i, &label)| (label, latency_buckets[i]))
                        .collect::<Vec<_>>()
                )
                .bar_width(8)
                .value_style(Style::default().fg(Color::Cyan));
            
            
            
            // **Render Widgets**
            frame.render_widget(system_status, top_row[0]);
            frame.render_widget(db_chart, mid_row[0]);
            frame.render_widget(rate_sparkline, mid_row[1]);
            frame.render_widget(cpu_sparkline, top_row[1]);
            frame.render_widget(latency_chart, mid_row[2]); // Show latency histogram
        
            let request_list = List::new(recent_requests)
                .block(Block::default().title("API Requests").borders(Borders::ALL));
            let error_log = List::new(recent_errors)
                .block(Block::default().title("Recent Errors").borders(Borders::ALL));
        
            frame.render_widget(request_list, bottom_row[0]);
            frame.render_widget(error_log, bottom_row[1]);
        }).expect("Failed to render TUI");
        
    }
}