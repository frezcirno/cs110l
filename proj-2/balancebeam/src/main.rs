mod request;
mod response;

use clap::Clap;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::time::delay_for;

/// Contains information parsed from the command-line invocation of balancebeam. The Clap macros
/// provide a fancy way to automatically construct a command-line argument parser.
#[derive(Clap, Debug)]
#[clap(about = "Fun with load balancing")]
struct CmdOptions {
    #[clap(
        short,
        long,
        about = "IP/port to bind to",
        default_value = "0.0.0.0:1100"
    )]
    bind: String,
    #[clap(short, long, about = "Upstream host to forward requests to")]
    upstream: Vec<String>,
    #[clap(
        long,
        about = "Perform active health checks on this interval (in seconds)",
        default_value = "10"
    )]
    active_health_check_interval: usize,
    #[clap(
        long,
        about = "Path to send request to for active health checks",
        default_value = "/"
    )]
    active_health_check_path: String,
    #[clap(
        long,
        about = "Maximum number of requests to accept per IP per minute (0 = unlimited)",
        default_value = "0"
    )]
    max_requests_per_minute: usize,
}

pub struct Upstream {
    address: String,
    failed: RwLock<bool>,
}

impl Upstream {
    pub fn new(address: String) -> Upstream {
        Upstream {
            address,
            failed: RwLock::new(false),
        }
    }
}

pub async fn health_check(address: &str, path: &str) -> bool {
    let maybe_stream = TcpStream::connect(address).await;
    if let Err(e) = maybe_stream {
        log::error!("Error connecting to upstream: {}", e);
        return false;
    }
    let mut stream = maybe_stream.unwrap();
    let request = http::Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", address)
        .body(Vec::new())
        .unwrap();
    if let Err(res) = request::write_to_stream(&request, &mut stream).await {
        log::error!(
            "Failed to send health check request to {}: {}",
            address,
            res
        );
        return false;
    }
    let maybe_resp = response::read_from_stream(&mut stream, request.method()).await;
    if let Err(err) = maybe_resp {
        log::error!(
            "Failed to read health check response from {}: {:#?}",
            address,
            err
        );
        return false;
    }
    let resp = maybe_resp.unwrap();
    if resp.status() != http::StatusCode::OK {
        log::error!(
            "Health check response from {} was not OK: {}",
            address,
            resp.status()
        );
        return false;
    }
    true
}

pub fn start_thread(upstream: Arc<Upstream>, path: String, interval: usize) {
    tokio::spawn(async move {
        loop {
            delay_for(std::time::Duration::from_secs(interval as u64)).await;
            let res = !health_check(&upstream.address, &path).await;
            *upstream.failed.write().unwrap() = res;
        }
    });
}

struct Window {
    start: std::time::Instant,
    counter: usize,
    max_requests_per_window: usize,
}

impl Window {
    pub fn new(max_requests_per_window: usize) -> Window {
        Window {
            start: std::time::Instant::now(),
            counter: 0,
            max_requests_per_window,
        }
    }

    pub fn is_limited(&self) -> bool {
        let time = std::time::Instant::now();
        if time.duration_since(self.start).as_secs() > 60 {
            return false;
        }
        self.counter >= self.max_requests_per_window
    }

    pub fn increment(&mut self) {
        let time = std::time::Instant::now();
        if time.duration_since(self.start).as_secs() > 60 {
            self.start = time;
            self.counter = 0;
        }
        self.counter += 1;
    }
}

/// Contains information about the state of balancebeam (e.g. what servers we are currently proxying
/// to, what servers have failed, rate limiting counts, etc.)
///
/// You should add fields to this struct in later milestones.
struct ProxyState {
    /// How frequently we check whether upstream servers are alive
    active_health_check_interval: usize,
    /// Where we should send requests when doing active health checks
    active_health_check_path: String,
    /// Maximum number of requests an individual IP can make in a minute
    max_requests_per_minute: usize,
    /// Addresses of servers that we are proxying to
    upstreams: Vec<Arc<Upstream>>,

    limits: RwLock<HashMap<String, Window>>,
}

#[tokio::main]
async fn main() {
    // Initialize the logging library. You can print log messages using the `log` macros:
    // https://docs.rs/log/0.4.8/log/ You are welcome to continue using print! statements; this
    // just looks a little prettier.
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::init();

    // Parse the command line arguments passed to this program
    let options = CmdOptions::parse();
    if options.upstream.len() < 1 {
        log::error!("At least one upstream server must be specified using the --upstream option.");
        std::process::exit(1);
    }

    // Start listening for connections
    let mut listener = match TcpListener::bind(&options.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("Could not bind to {}: {}", options.bind, err);
            std::process::exit(1);
        }
    };
    log::info!("Listening for requests on {}", options.bind);

    // Handle incoming connections
    let state = Arc::new(ProxyState {
        upstreams: options
            .upstream
            .iter()
            .map(|u| Arc::new(Upstream::new(u.to_string())))
            .collect(),
        active_health_check_interval: options.active_health_check_interval,
        active_health_check_path: options.active_health_check_path,
        max_requests_per_minute: options.max_requests_per_minute,
        limits: RwLock::new(HashMap::new()),
    });

    // Start health check threads
    for upstream in state.upstreams.iter() {
        start_thread(
            upstream.clone(),
            state.active_health_check_path.clone(),
            state.active_health_check_interval,
        );
    }

    while let Some(stream) = listener.next().await {
        if let Ok(stream) = stream {
            // Handle the connection!
            let clone = state.clone();
            tokio::spawn(async move {
                handle_connection(stream, clone).await;
            });
        }
    }
}

async fn connect_to_upstream(state: Arc<ProxyState>) -> Result<TcpStream, std::io::Error> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut upstream_index = rng.gen_range(0, state.upstreams.len());
    for _ in 0..state.upstreams.len() {
        let upstream = &state.upstreams[upstream_index];
        if *upstream.failed.read().unwrap() {
            continue;
        }
        match TcpStream::connect(&upstream.address).await {
            Ok(stream) => {
                return Ok(stream);
            }
            Err(err) => {
                log::error!("Could not connect to {}: {}", upstream.address, err);
                *upstream.failed.write().unwrap() = true;
            }
        }
        upstream_index = (upstream_index + 1) % state.upstreams.len();
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Could not connect to any upstream servers",
    ))
}

async fn send_response(client_conn: &mut TcpStream, response: &http::Response<Vec<u8>>) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!(
        "{} <- {}",
        client_ip,
        response::format_response_line(&response)
    );
    if let Err(error) = response::write_to_stream(&response, client_conn).await {
        log::warn!("Failed to send response to client: {}", error);
        return;
    }
}

async fn handle_connection(mut client_conn: TcpStream, state: Arc<ProxyState>) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!("Connection received from {}", client_ip);

    // Initialize the window for this client
    if state.max_requests_per_minute > 0 && !state.limits.read().unwrap().contains_key(&client_ip) {
        let mut wlimits = state.limits.write().unwrap();
        if !wlimits.contains_key(&client_ip) {
            wlimits.insert(
                client_ip.clone(),
                Window::new(state.max_requests_per_minute),
            );
        }
    }

    // Open a connection to a random destination server
    let mut upstream_conn = match connect_to_upstream(state.clone()).await {
        Ok(stream) => stream,
        Err(_error) => {
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
    };
    let upstream_ip = upstream_conn.peer_addr().unwrap().ip().to_string();

    // The client may now send us one or more requests. Keep trying to read requests until the
    // client hangs up or we get an error.
    loop {
        // Read a request from the client
        let mut request = match request::read_from_stream(&mut client_conn).await {
            Ok(request) => request,
            // Handle case where client closed connection and is no longer sending requests
            Err(request::Error::IncompleteRequest(0)) => {
                log::debug!("Client finished sending requests. Shutting down connection");
                return;
            }
            // Handle I/O error in reading from the client
            Err(request::Error::ConnectionError(io_err)) => {
                log::info!("Error reading request from client stream: {}", io_err);
                return;
            }
            Err(error) => {
                log::debug!("Error parsing request: {:?}", error);
                let response = response::make_http_error(match error {
                    request::Error::IncompleteRequest(_)
                    | request::Error::MalformedRequest(_)
                    | request::Error::InvalidContentLength
                    | request::Error::ContentLengthMismatch => http::StatusCode::BAD_REQUEST,
                    request::Error::RequestBodyTooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
                    request::Error::ConnectionError(_) => http::StatusCode::SERVICE_UNAVAILABLE,
                });
                send_response(&mut client_conn, &response).await;
                continue;
            }
        };

        if state.max_requests_per_minute > 0 {
            // Check if the window is full
            if state
                .limits
                .read()
                .unwrap()
                .get(&client_ip)
                .unwrap()
                .is_limited()
            {
                let response = http::Response::builder()
                    .status(429)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(format!("Too many requests from {}", &client_ip).into_bytes())
                    .unwrap();
                send_response(&mut client_conn, &response).await;
                continue;
            }

            // Add one to the window for this client
            let mut wlimit = state.limits.write().unwrap();
            let limiter = wlimit.get_mut(&client_ip).unwrap();
            limiter.increment();
            drop(wlimit);
        }

        log::info!(
            "{} -> {}: {}",
            client_ip,
            upstream_ip,
            request::format_request_line(&request)
        );

        // Add X-Forwarded-For header so that the upstream server knows the client's IP address.
        // (We're the ones connecting directly to the upstream server, so without this header, the
        // upstream server will only know our IP, not the client's.)
        request::extend_header_value(&mut request, "x-forwarded-for", &client_ip);

        // Forward the request to the server
        if let Err(error) = request::write_to_stream(&request, &mut upstream_conn).await {
            log::error!(
                "Failed to send request to upstream {}: {}",
                upstream_ip,
                error
            );
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
        log::debug!("Forwarded request to server");

        // Read the server's response
        let response = match response::read_from_stream(&mut upstream_conn, request.method()).await
        {
            Ok(response) => response,
            Err(error) => {
                log::error!("Error reading response from server: {:?}", error);
                let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
                send_response(&mut client_conn, &response).await;
                return;
            }
        };
        // Forward the response to the client
        send_response(&mut client_conn, &response).await;
        log::debug!("Forwarded response to client");
    }
}
