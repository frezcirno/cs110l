mod request;
mod response;

use clap::Clap;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use threadpool::ThreadPool;

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
    failed: Mutex<bool>,
}

impl Upstream {
    pub fn new(address: String) -> Upstream {
        Upstream {
            address,
            failed: Mutex::new(false),
        }
    }
}

pub fn health_check(address: &str, path: &str) -> bool {
    let maybe_stream = TcpStream::connect(address);
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
    if let Err(res) = request::write_to_stream(&request, &mut stream) {
        log::error!(
            "Failed to send health check request to {}: {}",
            address,
            res
        );
        return false;
    }
    let maybe_resp = response::read_from_stream(&mut stream, request.method());
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
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(interval as u64));
        let res = !health_check(&upstream.address, &path);
        *upstream.failed.lock().unwrap() = res;
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
        if self.max_requests_per_window == 0 {
            return false;
        }
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
    /// How frequently we check whether upstream servers are alive (Milestone 4)
    active_health_check_interval: usize,
    /// Where we should send requests when doing active health checks (Milestone 4)
    active_health_check_path: String,
    /// Maximum number of requests an individual IP can make in a minute (Milestone 5)
    max_requests_per_minute: usize,
    /// Addresses of servers that we are proxying to
    upstreams: Vec<Arc<Upstream>>,

    limits: RwLock<HashMap<String, Window>>,
}

fn main() {
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
    let listener = match TcpListener::bind(&options.bind) {
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

    let cpu_count = num_cpus::get();
    let thread_pool = ThreadPool::new(cpu_count);

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            // Handle the connection!
            let clone = state.clone();
            thread_pool.execute(|| handle_connection(stream, clone));
        }
    }
}

fn connect_to_upstream(state: Arc<ProxyState>) -> Result<TcpStream, std::io::Error> {
    let mut good_upstreams: Vec<_> = state
        .upstreams
        .iter()
        .filter(|u| !*u.failed.lock().unwrap())
        .collect();

    let mut rng = rand::rngs::StdRng::from_entropy();
    good_upstreams.shuffle(&mut rng);

    for upstream in good_upstreams {
        match TcpStream::connect(&upstream.address) {
            Ok(stream) => {
                return Ok(stream);
            }
            Err(err) => {
                log::error!("Could not connect to {}: {}", upstream.address, err);
                *upstream.failed.lock().unwrap() = true;
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Could not connect to any upstream servers",
    ))
}

fn send_response(client_conn: &mut TcpStream, response: &http::Response<Vec<u8>>) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!(
        "{} <- {}",
        client_ip,
        response::format_response_line(&response)
    );
    if let Err(error) = response::write_to_stream(&response, client_conn) {
        log::warn!("Failed to send response to client: {}", error);
        return;
    }
}

fn handle_connection(mut client_conn: TcpStream, state: Arc<ProxyState>) {
    let mut maybe_upstream_conn: Option<TcpStream> = None;
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!("Connection received from {}", client_ip);

    // Initialize the window for this client
    if !state.limits.read().unwrap().contains_key(&client_ip) {
        let mut wlimits = state.limits.write().unwrap();
        if !wlimits.contains_key(&client_ip) {
            wlimits.insert(
                client_ip.clone(),
                Window::new(state.max_requests_per_minute),
            );
        }
    }

    // The client may now send us one or more requests. Keep trying to read requests until the
    // client hangs up or we get an error.
    loop {
        // Read a request from the client
        let mut request = match request::read_from_stream(&mut client_conn) {
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
                send_response(&mut client_conn, &response);
                continue;
            }
        };

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
            send_response(&mut client_conn, &response);
            continue;
        }

        // Add one to the window for this client
        let mut wlimit = state.limits.write().unwrap();
        let limiter = wlimit.get_mut(&client_ip).unwrap();
        limiter.increment();
        drop(wlimit);

        // Open a connection to a random destination server
        if maybe_upstream_conn.is_none() {
            maybe_upstream_conn = match connect_to_upstream(state.clone()) {
                Ok(stream) => Some(stream),
                Err(_error) => {
                    let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
                    send_response(&mut client_conn, &response);
                    return;
                }
            };
        }
        let mut upstream_conn = maybe_upstream_conn.as_mut().unwrap();

        let upstream_ip = upstream_conn.peer_addr().unwrap().ip().to_string();

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
        if let Err(error) = request::write_to_stream(&request, &mut upstream_conn) {
            log::error!(
                "Failed to send request to upstream {}: {}",
                upstream_ip,
                error
            );
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response);
            return;
        }
        log::debug!("Forwarded request to server");

        // Read the server's response
        let response = match response::read_from_stream(&mut upstream_conn, request.method()) {
            Ok(response) => response,
            Err(error) => {
                log::error!("Error reading response from server: {:?}", error);
                let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
                send_response(&mut client_conn, &response);
                return;
            }
        };
        // Forward the response to the client
        send_response(&mut client_conn, &response);
        log::debug!("Forwarded response to client");
    }
}
