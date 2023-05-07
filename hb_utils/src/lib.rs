use serde::Serialize;
use hyper::{http::{HeaderName, HeaderValue}};
use http_body_util::{BodyExt};

use std::{net::{Ipv4Addr}};
use serde_json;

lazy_static::lazy_static! { 
    pub static ref CONTAINS_IP: Vec<HeaderName> = vec![
        HeaderName::from_static("x-forwarded-from"),
        HeaderName::from_static("x-real-ip"),
    ];
}

#[derive(Debug, Clone, Copy)]
pub enum OriginError {
    UnableToDetermineHost,
    IsLocalhost,
    OnlySocket(Ipv4Addr),
}


/// Operate on a Result, converting the error to a different type if one is encountered.
/// Designed to be used with `?`. For example:
/// ```
/// #![feature(iterator_try_collect)]
/// # #[derive(Debug)]
/// # enum MyError {FailedToParse,}
/// # use hb_utils::ConvertError;
/// let spaced_list_good = String::from("1 2 3 4 5");
/// let nums: Vec<u32> = spaced_list_good.split(" ")
///     .map(|s| s.parse::<u32>())
///     .try_collect()
///     .convert_error(MyError::FailedToParse)?;
/// # Ok::<(), MyError>(())
/// ```
/// ```should_panic
/// #![feature(iterator_try_collect)]
/// # use hb_utils::ConvertError;
/// # #[derive(Debug)]
/// # enum MyError {FailedToParse,}
/// let spaced_list_bad = String::from("C 0 W");
/// let nums: Vec<u32> = spaced_list_bad.split(" ")
///     .map(|s| s.parse::<u32>())
///     .try_collect()
///     .convert_error(MyError::FailedToParse)?;
/// # Ok::<(), MyError>(())
/// ```
pub trait ConvertError<T, E> {
    fn convert_error<E2>(self, err: E2) -> Result<T, E2>;
    fn convert_error_wrapping<E2>(self) -> Result<T, E2>
        where E2: From<E>;
        
}
impl<T, E> ConvertError<T, E> for Result<T, E> {
    fn convert_error<E2>(self, err: E2) -> Result<T, E2> {
        match self {
            Ok(val) => Ok(val),
            Err(_) => Err(err),
        }
    }
    fn convert_error_wrapping<E2>(self) -> Result<T, E2> 
    where
        E2: From<E> {
        match self {
            Ok(val) => Ok(val),
            Err(e) => Err(e.into()),
        }
    }
}

/// Designed to convert a bool to an error when using the `?` operator
/// For example:
/// ```should_panic
/// # use std::path::Path;
/// # use hb_utils::BoolError;
/// # #[derive(Debug)]
/// # enum MyError {FailedToParse, FileNotFound}
/// let config_path: &Path = Path::new("./foo/bar");
/// config_path.exists().bool_error(MyError::FileNotFound)?;
/// # Ok::<(), MyError>(())
/// ```
pub trait BoolError {
    fn bool_error<E>(self, err: E) -> Result<bool, E>;
}
impl BoolError for bool {
    fn bool_error<E>(self, err: E) -> Result<bool, E> {
        match self {
            true  => Ok(true),
            false => Err(err),
        }
    }
}

/// Returns the larger of two values.
/// Written because normally I would use a ternary operator here and rust does not support ternary
/// operators. :(
/// # Examples
/// ```
/// # use hb_utils::greatest;
/// let two: u32 = 2;
/// let six: u32 = 6;
/// assert_eq!(greatest(&two, &six), &six);
/// ```
#[inline]
pub fn greatest<'a, T>(x: &'a T, y: &'a T) -> &'a T
    where
    T: Ord
{
    if x >= y {
        return x;
    } else {
        return y;
    }
}

pub fn least<'a, T>(x: &'a T, y: &'a T) -> &'a T
    where
    T: Ord
{
    if x <= y {
        return x
    } else {
        return y;
    }
}

pub struct SuccessWrapper<T> 
    where T: Serialize
{
    success: bool,
    obj: Option<T>,
    reason: Option<String>,
}

impl<T> SuccessWrapper<T>
    where T: Serialize
{
    pub fn new<E>(obj: Result<T, E>) -> SuccessWrapper<T>
    where T: Serialize,
          E: std::fmt::Debug
    {
        match obj {
            Ok(k) => {
                SuccessWrapper {
                    success: true,
                    obj: Some(k),
                    reason: None,
                }
            }
            Err(err) => {
                SuccessWrapper {
                    success: false,
                    obj: None,
                    reason: Some(format!("{:?}", err)),
                }
            }
        }
    }

    pub fn simple_serialize(self) -> serde_json::Value {
        match self.success {
            true => {
                serde_json::json! ({
                    "success": true,
                    // TODO: Error handling here!
                    "result": serde_json::to_value(&self.obj.unwrap()).unwrap()
                })
            }
            false => {
                serde_json::json! ({
                    "success": false,
                    "reason": self.reason.unwrap()
                })
            }
        }
    }
}

// ==================================================================================================== //
//                                Server related helper functions and macros
// ==================================================================================================== //

pub fn parse_ip(addr: &str) -> Option<Ipv4Addr> {
    let cleaned = if addr.contains(":") {
        addr.split(":").next().unwrap()
    } else {
        addr
    };
    let octets: Vec<u8> = cleaned
        .split(".")
        .map(|s| s.parse::<u8>())
        .filter(|s| s.is_ok())
        .map(|s| s.unwrap())
        .collect();
    if let Ok(octets) = TryInto::<[u8; 4]>::try_into(octets) {
        Some(Ipv4Addr::from(octets))
    } else {
        None
    }
    // If I had not been avoiding unstable, and had I figured out hwo to do the other shit,
    // I would have been
    // ```
    // let octets: [u8; 4] = octets[..]
    //      .try_into()
    //      .convert_error...,
    // ```
}


/// NOTE:
/// This function is designed for use with the server. Because of this, the return type is unusual
pub fn extract_ip_from_headers(headers: &hyper::header::HeaderMap, s_addr: Ipv4Addr) -> Result<Ipv4Addr, OriginError> {
    // filter down to usable IPs
    let itr = headers.iter();
    let possible: Vec<(&HeaderName, &HeaderValue)> = itr.filter(|i| CONTAINS_IP.contains(&i.0)).collect();
    if possible.len() == 0 {
        return Err(OriginError::OnlySocket(s_addr));
    }
    // check for x-real-ip
    if let Some(ip) = headers.get("x-real-ip") {
        let addr = parse_ip(ip.to_str().unwrap()).unwrap();
        if addr.is_loopback() {
            return Err(OriginError::IsLocalhost);
        } else {
            return Ok(addr);
        }
    } else if let Some(ip) = headers.get("x-forwarded-from") {
        let addr = parse_ip(ip.to_str().unwrap()).unwrap();
        if addr.is_loopback() {
            return Err(OriginError::IsLocalhost);
        } else {
            return Ok(addr);
        }
    } else { 
        return Err(OriginError::OnlySocket(s_addr));
    }
}

#[macro_export]
macro_rules! jsonify {
    (body: $body:expr, stat: $stat:expr) => {
        Response::builder()
            .status($stat)
            .header("Content-Type", "Application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .body(Full::new(Bytes::from(format!("{{\"success\":\"true\",\"result\":{}}}",serde_json::to_string(&$body).unwrap()))))
    };
}

/// TODO!!!!!!!!!
/// Please remember to document this!
#[macro_export]
macro_rules! failure_from_code {
    ($status:expr) => {
        hb_utils::failure_from_code!($status, "");
    };
    ($status:expr, $msg:expr) => {
        Response::builder()
            .status($status)
            .header("Content-Type", "application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .body(Full::new(Bytes::from(String::from(format!("\"success\": false,\"reason\": \"{}\n{}\"", $status.canonical_reason().unwrap(), $msg))))).unwrap();
    };
}

//=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-   THIS IS THE TESTING CODE SECTION     =-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-   IT IS UGLY TESTING CODE, BUT ITS     =-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-             GOOD ENOUGH!!              =-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#[cfg(test)]
mod tests{
    use std::fmt;
    use crate::*;
    use super::*;
    use std::path::Path;

    #[test]
    fn test_greatest() {
        let two: u32 = 2;
        let six: u32 = 6;
        assert!(greatest(&two, &six) == &six);
    }

    #[derive(Debug)]
    enum MyCustomError {
        UhOh
    }

    #[derive(Debug)]
    enum OtherError {
        ImFromAnotherCrate
    }
    impl std::error::Error for OtherError {}
    impl fmt::Display for OtherError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ERROR")
        }
    }

    impl std::error::Error for MyCustomError {}
    impl fmt::Display for MyCustomError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Uh oh...")
        }
    }


    #[test]
    #[should_panic(expected = "UhOh")]
    fn test_errors_error() ->  () {
        // we are forcing an unwrap of an error, since I can't assert Err(_) == Err(_)
        bad_divide(1, 0).convert_error(MyCustomError::UhOh).unwrap();
        return ();

        fn bad_divide(n:u32, d:u32) -> Result<u32, Box<dyn std::error::Error>>{
            if d == 0 {
                Err(Box::new(OtherError::ImFromAnotherCrate))
            } else {
                Ok(n/d)
            }
        }
    }

    #[test]
    fn test_errors_safe() -> Result<(), MyCustomError> {
        assert!(return_three().convert_error(MyCustomError::UhOh)? == 3);
        return Ok(());

        fn return_three() -> Result<u32, Box<dyn std::error::Error>> { Ok(3) }
    }

    #[test]
    fn bool_error_true() -> Result<(), Box<dyn std::error::Error>> {
        use std::path::Path;
        Path::new("/").exists().bool_error(MyCustomError::UhOh)?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn bool_error_false() -> () {
        use std::path::Path;
        Path::new("/thispathdoesntexist/jkaldawoduhaiwdojalkwdawdoijadhawdowad").exists().bool_error(MyCustomError::UhOh).unwrap();
    }

    #[derive(Debug)]
    enum ErrorWrapper {
        MiscError,
        IOError(std::io::Error),
    }

    impl From<std::io::Error> for ErrorWrapper {
        fn from(error: std::io::Error) -> Self {
            ErrorWrapper::IOError(error)
        }
    }

    #[test]
    fn wrapping_test() -> () {
        use std::io::BufReader;
        use std::path::Path;
        let p = Path::new("/jakhsjdkujgdjghgakhwjdbjhajwdudhawdkjawd/asidkuahwd.kkjiads");
        let f = dbg!(std::fs::File::open(p).convert_error_wrapping::<ErrorWrapper>());
        match f {
            Ok(_) => panic!("Why do you have a path on root with that name!"),
            Err(ErrorWrapper::IOError(e)) => assert!(e.raw_os_error().unwrap() == 2),
            _ => panic!("Should not be reached!")
        }
    }

    #[test]
    fn test_ips_conversion() -> () {
        use super::parse_ip;
        let ips = vec![
            "192.168.1.1"    , "10.23.25.29"    , "69.13.182.244"  , "27.16.113.97",
            "1.2.3.4"        , "100.200.100.200", "32.32.32.32"    , "123.123.123.123",
            "172.0.0.1"      , "13.231.147.73"  , "101.101.1.100"  , "1.1.1.1",
            "105.115.124.3"  , "213.49.153.252" , "230.106.20.188" , "107.8.37.127",
            "8.83.108.236"   , "46.52.130.27"   , "254.175.154.206", "122.178.104.248",
            "193.250.37.128" , "174.32.35.91"   , "80.14.154.196"  , "93.145.22.114",
            "223.173.132.165", "148.144.89.164" , "84.3.66.59"     , "128.139.129.158",
            "214.125.233.239", "16.26.229.172"  , "177.22.2.38"    , "12.189.55.122",
            "11.167.15.209"  , "139.255.144.154", "237.15.119.68"  , "211.119.51.56",
            "20.11.158.14"   , "25.24.224.111"  , "152.55.219.166" , "115.39.29.33",
            "129.250.57.130" , "124.222.240.155", "59.1.253.119"   , "255.122.231.94"
        ]; 
        
        for ip in ips {
            let parsed = parse_ip(ip).unwrap();
            let s = parsed.to_string();
            assert_eq!(s, ip);
        }
    }
}
