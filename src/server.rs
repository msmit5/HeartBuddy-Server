/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use std::os::unix::fs::PermissionsExt;
use crate::args::CfgStatus;
use crate::feature_extractor::{FeatureExtractor, FeatureExtractorError};
use crate::ml_controller::{InputFormat, MLError};
use crate::ml_controller::{tensor_from_numpy_file, ML_Controller, ML_Input};
use crate::ratelimit::{RL_Response, RateLimiterError};
use crate::ratelimit::RateLimiter;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use hb_utils::{BoolError, ConvertError, SuccessWrapper};
use http_body_util::{BodyExt, Full};
use hyper::http::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Body, Method, Request, Response, StatusCode};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::error::Error as Std_Error;
use std::{fmt, usize, fs};
use std::fs::File;
use std::io::{Write, BufReader};
use std::net::{SocketAddr, IpAddr};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use uuid::Uuid;



#[derive(Debug)]
#[allow(dead_code)]
pub enum HBServerError {
    FailedToBindAddress,
    IllegalIP,
    BadArgs,
    BadConfig,
    PermissionsError,
    SigIntReceived,
    ChannelFailure,
    IOError(std::io::Error),
    RateLimitFailure(RateLimiterError),
    MLFailure(MLError),
    #[allow(dead_code)] // Might never be used, still necessary.
    Unknown(Box<dyn std::error::Error>),
}

impl std::error::Error for HBServerError {}

impl fmt::Display for HBServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HBServerError::FailedToBindAddress => write!(f, "Unable to bind address!"),
            HBServerError::BadArgs => write!(f, "Unable to parse arguments into a server config"),
            HBServerError::Unknown(e) => write!(f, "An undefined, unknwon error occured!\n{:#?}", e),
            HBServerError::IllegalIP => write!(f, "Provided argument for IP address is illegal"),
            HBServerError::SigIntReceived => write!(f, "SIGINT Was received"),
            HBServerError::ChannelFailure => write!(f, "Signal handler channel closed! Without channel, the program will becore irresponsive to all signals!\nShutting down!"),
            HBServerError::BadConfig => write!(f, "Failed to parse config file!"),
            HBServerError::PermissionsError => write!(f, "Server config should not have o+rwx"),
            HBServerError::IOError(e) => write!(f, "IO Failure! Reason: {:?}", e.kind()),
            HBServerError::RateLimitFailure(e) => write!(f, "Rate limiter error: {}", e),
            HBServerError::MLFailure(e) => write!(f, "ML Failure! Reason:\n{}", e),
        }
    }
}

impl From<std::io::Error> for HBServerError {
    fn from(e: std::io::Error) -> Self {
        HBServerError::IOError(e)
    }
}

impl From<RateLimiterError> for HBServerError {
    fn from(e: RateLimiterError) -> Self {
        HBServerError::RateLimitFailure(e)
    }
}

impl From<MLError> for HBServerError {
    fn from(e: MLError) -> Self {
        HBServerError::MLFailure(e)
    }
}


#[derive(Debug, Deserialize)]
pub struct Config {
    addr: SocketAddr,
    r1w: Duration,
    r1m: u32,
    r2w: Duration,
    r2m: u32,
    // #[allow(dead_code)] // Not used currently, used in future
    // firewall_ban: bool,
    manifest_loc: String,
    fex_loc: String,
}

#[derive(Debug, Deserialize)]
pub enum BiologicalSex {
    Male,
    Female,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PredictRequest {
    prediction_type: PredictType,
    age: u8,
    sex: BiologicalSex,
    weight: u8,
    height: u8,
    payload_b64: String,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum PredictType {
    Numpy,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelPredictionResponse {
    name: String,
    acronym: String,
    success: bool,
    predict_tensor_l: f32,
    predict_tensor_r: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PredictResponse {
    predictions: Vec<ModelPredictionResponse>,
    fex_image: String,
}


impl Config {

    #[allow(dead_code)] // Used for testing.
    pub fn testing_default() -> Config {
        Config {
            addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            r1w: Duration::from_secs(5),
            r1m: 3,
            r2w: Duration::from_secs(0),
            r2m: 0,
            // firewall_ban: false,
            fex_loc: "/var/models/fex.py".to_string(),
            manifest_loc: "/var/models/manifest.json".to_string(),
        }
    }

    fn from_file(p: &Path) -> Result<Config, HBServerError> {
        // check if path exists
        p.exists().bool_error(HBServerError::BadArgs)?;

        // check file permissions
        // We don't want write permissions on the config, or a bad actor could disable security
        // features such as rate limiting, or point to a manifest with malicious tensorflow args,
        // as tensorflow models can run arbitrary code
        let meta = std::fs::metadata(p).convert_error_wrapping::<HBServerError>()?;
        if meta.permissions().mode() % 10 != 0 {
            return Err(HBServerError::PermissionsError);
        }

        // let f = File::open(p).convert_error_wrapping(HBServerError::IOError);
        let f = File::open(p).convert_error_wrapping::<HBServerError>()?;
        let reader = BufReader::new(f);
        Ok(serde_json::from_reader(reader).convert_error(HBServerError::BadConfig)?)
    }

    pub fn from_args(a: crate::args::Args) -> Result<Config, HBServerError> {
        match a.config_exists() {
            CfgStatus::FileExists => {
                info!("Configuration file provided. Any additional arguments will be ignored.");
                return Config::from_file(a.get_path().convert_error(HBServerError::BadArgs)?);
            }
            CfgStatus::FileNotExists => {
                error!("Path `{:?}` was provided, but the file does not exist!", a.get_path().unwrap());
                return Err(HBServerError::BadArgs);
            }
            CfgStatus::NoArg => {} // Continue
        }

        
        let (addr, port, r1_w, r1_m, r2_w, r2_m, _fw_ban, _, mani, script) = a.unravel();

        let octets: Vec<u8> = addr
            .split(".")
            .map(|s| s.parse::<u8>())
            .try_collect()
            .convert_error(HBServerError::IllegalIP)?;
        let octets: [u8;4] = octets[..]
            .try_into()
            .convert_error(HBServerError::IllegalIP)?;

        let sock_addr = SocketAddr::from((octets, port));

        Ok(Config {
            addr: sock_addr,
            r1w: Duration::from_millis(r1_w),
            r1m: r1_m,
            r2w: Duration::from_millis(r2_w),
            r2m: r2_m,
            manifest_loc: mani,
            fex_loc: script,
        })
    }

    pub const fn get_addr(&self) -> SocketAddr {
        return self.addr;
    }

    pub const fn get_ratelimits(&self) -> (Duration, u32, Duration, u32) {
        return (self.r1w, self.r1m, self.r2w, self.r2m);
    }
} // impl config


pub async fn run(cfg: Config) -> Result<(), HBServerError> {
    
    info!("Starting server!");

    let a = cfg.addr;
    let listener = TcpListener::bind(a)
        .await
        .convert_error(HBServerError::FailedToBindAddress)?;
    info!("Bound server on {:?}", a);

    let (r1w, r1m, r2w, r2m) = cfg.get_ratelimits();
    
    let rate_limiter = Arc::new(
        RateLimiter::init(r1w, r1m, r2w, r2m)
            .convert_error_wrapping::<HBServerError>()?
        );

    let (tx, mut rx): (Sender<()>, Receiver<()>) = channel(1);
    let mut tokio_pool = JoinSet::new();
    tokio_pool.spawn(unix_signal_handler(tx));

    let ml_ctrl = Arc::new(ML_Controller::new(PathBuf::from(cfg.manifest_loc))?);
    let fex_ctrl = Arc::new(FeatureExtractor::new(cfg.fex_loc));
    
    //---------------------------------------------------------------//
    //  This is the main server loop!
    let loop_res: Result<(), HBServerError> = loop {
        tokio::select! {
            // Handle SIGINT
            _ = rx.recv() => {
                warn!("SIGINT received from signal handler!"); 
                warn!("Shutting down server!");
                break Err(HBServerError::SigIntReceived);
            }
            maybe_session = listener.accept() => {
                let (stream, sock_addr) = maybe_session.convert_error_wrapping::<HBServerError>()?;
                let cloned_rl = Arc::clone(&rate_limiter);
                let cloned_ml_controller = Arc::clone(&ml_ctrl);
                let cloned_fex = Arc::clone(&fex_ctrl);

                tokio_pool.spawn(async move {
                    // ML Controller shit was moved to the router because at that point it is
                    // easier to parse the packet and determine what is the real IP of the
                    // requester before sending to the ratelimiter
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(stream, service_fn(move |req| {
                            router(req, Arc::clone(&cloned_ml_controller), Arc::clone(&cloned_fex), Arc::clone(&cloned_rl), sock_addr)
                        }))
                    .await
                    {
                        error!("Error serving connection!\n{:#?}", e);
                    }
                });
            }
        }
    };
    // This is the end of the main server loop!
    //---------------------------------------------------------------//
    drop(rate_limiter);

    tokio::select! {
        _ = await_all_tasks(&mut tokio_pool) => {
            info!("Finished waiting for all tokio tasks!");
            drop(rx);
        }
        _ = rx.recv() => {
            warn!("Exiting before tokio threads can finish!");
            drop(rx);
        }
    }

    std::thread::sleep(Duration::from_millis(210));
    return loop_res;
}

async fn router(_req: Request<hyper::body::Incoming>, ml_ctrl: Arc<ML_Controller>, fex_controller: Arc<FeatureExtractor>, rl: Arc<RateLimiter>, sock_addr: SocketAddr) -> Result<Response<Full<Bytes>>, Box<dyn Std_Error + Send + Sync>> {
    // Check the ratelimiter to see if the address will be allowed
    let sock_ip: std::net::Ipv4Addr = match sock_addr.ip() {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => return Ok(hb_utils::failure_from_code!(StatusCode::BAD_REQUEST, "Server does not support IPv6 sockets!")),
    };
    let ip = match hb_utils::extract_ip_from_headers(&_req.headers(), sock_ip) {
        Ok(o) => std::net::IpAddr::from(o),
        Err(hb_utils::OriginError::OnlySocket(ip)) => {
            // Someone might want to require a proxy!
            // At this point, they'd return a failure_from_code!
            std::net::IpAddr::from(ip)
        },
        Err(hb_utils::OriginError::UnableToDetermineHost) => return Ok(hb_utils::failure_from_code!(StatusCode::BAD_REQUEST)),
        Err(hb_utils::OriginError::IsLocalhost) => {
            info!("received request from localhost. In order to prevent potential Denials of Service, localhost is excluded from ratelimiting");
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
    };
    if !ip.is_loopback() {
        match rl.check_ips(std::net::IpAddr::from(ip)).await {
            RL_Response::Allow => {},
            RL_Response::Deny =>{
                return Ok(hb_utils::failure_from_code!(StatusCode::TOO_MANY_REQUESTS));
            },
            RL_Response::Blocked =>{
                return Ok(hb_utils::failure_from_code!(StatusCode::TOO_MANY_REQUESTS));
            },
        }
    } // else: Do nothing because we don't want to block loopback
      

    match (_req.method(), _req.uri().path()) {
        (&Method::GET, "/ping") | (&Method::GET, "/ping/") => {
            let mut resp = Response::new(Full::new(Bytes::from("Pong!\n")));
            resp.headers_mut().insert(HeaderName::from_static("content-type"), HeaderValue::from_static("text/plain"));
            return Ok(resp);
        },
        (&Method::POST, "/upload") | (&Method::POST, "/upload/") => {
            info!("Processing upload!");
            return upload_prediction(_req, ml_ctrl, fex_controller).await;
        },
        (&Method::OPTIONS, "/upload") | (&Method::OPTIONS, "/upload/") => {
            return Ok(Response::builder()
                      .status(StatusCode::OK)
                      .header("Access-Control-Allow-Origin", "*")
                      .header("Access-Control-Allow-Methods", "OPTIONS, POST")
                      .header("Access-control-allow-headers", "Content-Type")
                      .header("Content-type", "Application/Json")
                      .body(Full::new(Bytes::from(""))).unwrap());
        },
        (_, uri) => {
            info!("Trying to serve non-existant API endpoint: {uri}");
            return Ok(hb_utils::failure_from_code!(StatusCode::NOT_FOUND));
        }

    }

}


async fn await_all_tasks(pool: &mut JoinSet<()>) -> () {
    info!("Awaiting all tokio tasks!");
    while let Some(_) = pool.join_next().await{ }
}

async fn unix_signal_handler(tx: Sender<()>) -> () {
    loop {
        tokio::select! {
            sig = signal::ctrl_c() => {
                match sig {
                    Err(e) => {
                        error!("Error recieved while initializing signal handler! THIS SHOULD NEVER HAPPEN!\n{:#?}", e);
                        // race condition if handler fails before listener is listened to.
                        std::thread::sleep(Duration::from_millis(25));
                        // TODO:
                        // Full panic handling a-la
                        // https://stackoverflow.com/questions/35988775/how-can-i-cause-a-panic-on-a-thread-to-immediately-end-the-main-thread
                        tx.send(()).await.unwrap();
                        tx.send(()).await.unwrap();
                        // PANIC JUSTIFICATION:
                        // If an error was recieved by the signal handler, the program can no
                        // longer shut down properly using SIGINT, therefore it is fine to shut
                        // to panic and cause the program to stop
                        panic!("Signal handler failure!");
                    }
                    Ok(_) => {
                        tx.send(()).await.unwrap();
                    }
                }
            }
            _ = tx.closed() => {
                warn!("Signal handler has detected that there are no more listeners! Shutting down thread!");
                return;
            }
        } // end select!
    }
}


async fn upload_prediction(req: Request<hyper::body::Incoming>, ml_ctrl: Arc<ML_Controller>, fex_controller: Arc<FeatureExtractor>) -> Result<Response<Full<Bytes>>, Box<dyn Std_Error + Send + Sync>> {
    let resp: Response<Full<Bytes>>;
    let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
    if upper > 1024 * 750 { // 750 KiB
        resp = hb_utils::failure_from_code!(StatusCode::PAYLOAD_TOO_LARGE);
        return Ok(resp);
    }

    // check if multipart
    let headers = req.headers().clone();
    let whole_body = req.collect().await?.to_bytes();
    let mut is_multipart: bool = false;
    // look for multipart/form-data
    if headers.iter().filter(|(_k, v)| v.to_str().unwrap().contains("multipart/form-data")).collect::<Vec<_>>().len() > 0 {is_multipart = true;}

    let incoming: PredictRequest;
    if is_multipart {
        // TODO: Re-implement by getting increment from header
        let body_start = whole_body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body_end = whole_body.windows(4).position(|w| w == b"\r\n--").unwrap();
        incoming = serde_json::from_slice(&whole_body[body_start..body_end]).unwrap();
    } else {
        incoming = serde_json::from_slice(&whole_body).unwrap();
    }

    match incoming.prediction_type {
        PredictType::Numpy => {
            let mut v: Vec<u8> = Vec::new();
            general_purpose::STANDARD.decode_vec(incoming.payload_b64, &mut v).unwrap();

            let id = Uuid::new_v4();
            // Because there is no good way to pass 600kb to a process without using a file, I will
            // use a file.
            let fpath = format!("/tmp/{id}");
            let mut f = File::create(&fpath).unwrap();
            let metadata = f.metadata()?;
            metadata.permissions().set_mode(0o600);

            f.write(&v)?;
            drop(f); // close the file
            
            let mut tf = tensor_from_numpy_file(&fpath)?;
            let input = ML_Input {
                input_format: InputFormat::Tensor,
                input_tensor: &mut tf,
            };

            // Normally, join! runs on a single thread, but I am hoping that run_process will be
            // nice and well behaved, and not block when it forks!
            let fex_fut = fex_controller.run_process(&fpath);
            let results_fut = ml_ctrl.predict(input);

            let (fex_res, pred_res) = tokio::join!(fex_fut, results_fut);
            
            let fex_wrapped= match fex_res {
                Ok(_) => {
                    assert!(std::path::Path::new(&format!("/tmp/{id}.png")).exists());
                    let img = std::fs::read(format!("/tmp/{id}.png")).unwrap();
                    let encoded_img = general_purpose::STANDARD.encode(img);
                    SuccessWrapper::new::<Result<String, FeatureExtractorError>>(Ok(encoded_img))
                },
                Err(e) => SuccessWrapper::new(Err(e)),
            };
            let mut model_responses: Vec<ModelPredictionResponse> = Vec::new();
            for i in 0..pred_res.len() {
                let manifest = ml_ctrl.get_manifest_entry(i as usize);
                let resp_part = ModelPredictionResponse{
                    name: manifest.get_cond_name(),
                    acronym: manifest.get_acronym(),
                    success: true,
                    predict_tensor_l: pred_res[i].as_ref().unwrap().res.as_ref().unwrap()[0],
                    predict_tensor_r: pred_res[i].as_ref().unwrap().res.as_ref().unwrap()[1],
                };
                model_responses.push(resp_part);
            }

            let predictions_wrapped = SuccessWrapper::new::<MLError>(Ok(model_responses));
            let resp = serde_json::json!({
                "predictions" : predictions_wrapped.simple_serialize(),
                "feature_extraction": fex_wrapped.simple_serialize()
            });
            let resp = serde_json::to_string(&resp).unwrap();
            let fpath_png = format!("{}.png", &fpath);
            let pre_shred = std::time::Instant::now();
            file_shred::shred_file(&std::path::Path::new(&fpath)).unwrap_or_else(|_| fs::remove_file(&fpath).expect("Failed to remove file!"));
            file_shred::shred_file(&std::path::Path::new(&fpath_png)).unwrap_or_else(|_| fs::remove_file(fpath_png).expect("Failed to remove png!"));
            let dur = pre_shred.duration_since(std::time::Instant::now());
            if dur > std::time::Duration::from_nanos(5){ 
                info!("It took {:?} to shred", dur);
            }

            return Ok(Response::builder()
                .status(200)
                .header("Content-Type", "Application/json")
                .header("access-control-allow-origin", "*")
                .header("access-control-allow-methods","OPTIONS, POST")
                .body(Full::new(Bytes::from(resp))).unwrap())
        }
        PredictType::Other => {
            return Ok(
                Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header("Content-Type", "Application/Json")
                    .body(Full::new(Bytes::from(r#"{"success":false,"reason":"HeartBuddy only supports Numpy""#))).unwrap()
            );
        }
    }

}
