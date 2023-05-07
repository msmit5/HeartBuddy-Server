/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread::{self as std_thread, JoinHandle};
use std::time::Duration;
//use hb_utils::greatest;
use std::sync::Mutex;
use tracing::{error, info, warn};
use std::error::Error as Std_Error;

#[derive(Debug)]
pub enum RateLimiterError {
    BadArgs,
    #[allow(dead_code)] // eventually useful, not used atm
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl std::error::Error for RateLimiterError {}

impl fmt::Display for RateLimiterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RateLimiterError::BadArgs => write!(f, "Invalid argument"),
            RateLimiterError::Other(err) => write!(f, "Extraneous error: {:?}", err),
        }
    }
}

#[allow(non_camel_case_types)]
pub enum RL_Response {
    Allow,
    Deny,
    #[allow(dead_code)] // eventually useful, not used atm
    Blocked,
}

#[allow(non_camel_case_types)]
struct RL_Map {
    #[allow(dead_code)] // Not used, but useful for debug printing
    window: Duration,
    max: u32,
    map: Arc<Mutex<HashMap<IpAddr, u32>>>,
    #[allow(dead_code)] // Dropping the thread handle is irresponsible.
    t_handle: Option<JoinHandle<()>>,
    #[allow(dead_code)] // The existence of the arc pointer is necessary. When it goes out of
    alive_dat: Arc<()>, // scope, the thread notices the Arc count goes to 1, and it exits.
}

pub struct RateLimiter {
    rl_1: RL_Map,
    rl_2: RL_Map,
    limiters: LimitersEnabled,
}
#[derive(PartialEq, Debug)]
enum LimitersEnabled {
    One(Duration, u32),
    Two,
    NoneEnabled,
}

impl RateLimiter {
    pub fn init(r1w: Duration, r1m: u32, r2w: Duration, r2m: u32) -> Result<RateLimiter, RateLimiterError> {
        //info!("Creating ratelimiter with: r1w: {:?}, r1m: {r1m}, r2w: {:?}, r2m: {r2m}", r1w, r2w);
        let mut count = 0;
        if r1w > Duration::ZERO {
            count += 1;
        }
        if r2w > Duration::ZERO {
            count += 1;
        }

        let num_limiters = match count {
            0 => LimitersEnabled::NoneEnabled,
            // Selecting the correct duration/max.
            1 => {
                if r1w > r2w {
                    LimitersEnabled::One(r1w, r1m)

                } else {
                    LimitersEnabled::One(r2w, r2m)
                }
            },
            2 => LimitersEnabled::Two,
            _ => panic!("Somehow, somewhere, A value not in {{0, 1, 2}} was passed to the first match statement in RateLimiter::init"),
        };

        // TODO: Make better for user
        info!("{:?}", num_limiters);

        if num_limiters == LimitersEnabled::NoneEnabled {
            warn!("RATE LIMITER NOT ENABLED! In most cases, this is not recommended!");
        } else {
            // check if there is invalid arguments
            // Invalid arguments are: Duration > 0 and Max == 0
            if (r1m == 0 && r1w > Duration::ZERO) || (r2m == 0 && r2w > Duration::ZERO) {
                return Err(RateLimiterError::BadArgs);
            }
        }

        // create the RateLimiter and the RL_Maps
        match num_limiters {
            LimitersEnabled::One(rlw, rlm) => {
                // Create RateLimiter struct and
                let rl = RateLimiter {
                    rl_1: RL_Map::init(rlw, rlm),
                    rl_2: RL_Map::empty(),
                    limiters: num_limiters,
                };
                Ok(rl)
            }
            LimitersEnabled::Two => {
                // Create RateLimiter struct and
                let rl = RateLimiter {
                    rl_1: RL_Map::init(r1w, r1m),
                    rl_2: RL_Map::init(r2w, r2m),
                    limiters: num_limiters,
                };
                Ok(rl)
            }
            LimitersEnabled::NoneEnabled => {
                // Create RateLimiter struct
                let rl = RateLimiter {
                    rl_1: RL_Map::empty(),
                    rl_2: RL_Map::empty(),
                    limiters: num_limiters,
                };
                Ok(rl)
            }
        }
    } // end init

    async fn one_limiter_controller(&self, ip_addr: IpAddr) -> RL_Response {
        return match !self.rl_1.is_ip_blocked(ip_addr) {
            true  => RL_Response::Allow,
            false => RL_Response::Deny,
        };
    }

    async fn two_limiter_controller(&self, ip: IpAddr) -> RL_Response {
        return match !self.rl_1.is_ip_blocked(ip)
            && !self.rl_2.is_ip_blocked(ip)
        {
            true  => RL_Response::Allow,
            false => RL_Response::Deny,
        };
    }

    #[inline(always)]
    async fn none_limiter_controller(&self) {} // Not needed

    pub async fn check_ips(&self, ip: IpAddr) -> RL_Response {
        match self.limiters {
            LimitersEnabled::One(_, _) => {
                return self.one_limiter_controller(ip).await;
            }
            LimitersEnabled::Two => {
                return self.two_limiter_controller(ip).await;
            }
            LimitersEnabled::NoneEnabled => {
                self.none_limiter_controller().await;
                return RL_Response::Allow;
            }
        }
    }
}

impl RL_Map {
    pub fn init(w: Duration, m: u32) -> RL_Map {
        // spawn clear thread
        let mut _map: Arc<Mutex<HashMap<IpAddr, u32>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut _map2 = Arc::clone(&_map);
        let _alive_dat: Arc<()> = Arc::new(());
        let thread_alive_dat = Arc::clone(&_alive_dat);
        // Separate the main sleep into smaller sleep chunks interrupted by checking if
        // owner is alive.
        let sleep_chunks = w.as_millis() / 200;
        let _t_handle = std_thread::spawn(move || {
            loop {
                for _ in 0..sleep_chunks {
                    // Check if owner is still alive
                    match Arc::strong_count(&thread_alive_dat) {
                        0 | 1 => {
                            // Because of threading, and the fact that this handle has most
                            // likely been dropped by the time that this thread learns of the
                            // owner has died, I want to deallocate the only object on the heap
                            drop(_map2);
                            warn!("Thread owner died! Is server shutting down?");
                            return;
                        }
                        _ => {} // Only kill thread if the thread owner drops self.alive_dat. This
                                // should only happen when the struct is memdropped.
                    }
                    std_thread::sleep(Duration::from_millis(200));
                } // end of sleep

                info!("Clearing RateLimiter hashmap");
                _map2.lock().unwrap().clear();
                // no need to unlock becuase the mutex guard returned by lock goes out of scope
                // when the .clear instruction is finished. The mutex guard destructor calls
                // unlock.
            }
        });
        return RL_Map {
            window: w,
            max: m,
            map: _map,
            t_handle: Some(_t_handle),
            alive_dat: _alive_dat,
        };
    }

    pub fn empty() -> RL_Map {
        return RL_Map {
            window: Duration::from_secs(86400),
            max: u32::MAX,
            map: Arc::new(Mutex::new(HashMap::new())),
            t_handle: None,
            alive_dat: Arc::new(()),
        };
    }

    #[allow(unused)] // Primarily for writing quick tests, might make it's way into a final build
    pub fn get_amt(&self, ip: IpAddr) -> u32 {
        loop {
            if let Ok(mut mutex) = self.map.try_lock() {
                match mutex.get(&ip) {
                    Some(x) => return *x,
                    None => {
                        error!("None returned by a get_amt! This shouldn't happen! unless the map was cleared while the request was made to get.\n map size: {}",
                               mutex.len());
                        return 0;
                    }
                }
            }
        }
    }

    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        loop {
            match self.map.try_lock() {
                Ok(mut mutex) => match mutex.get_mut(&ip) {
                    Some(x) => {
                        *x += 1;
                        return *x > self.max;
                    }
                    None => {
                        mutex.insert(ip, 1);
                        return 1 > self.max;
                    }
                },
                Err(_) => { /* Only error should be a failed lock acquire. This is mitigated with the loop. */
                }
            }
        }
    }
}
