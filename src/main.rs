#[macro_use]
extern crate lazy_static;

use hmac_sha256::HMAC;

use cookie::Cookie;
use std::str;

use fastly::http::{Method, StatusCode};
use fastly::{Body, ConfigStore, Error, Request, Response};

extern crate captcha;
use captcha::filters::Noise;
use captcha::Captcha;
use captcha::{gen, Difficulty};

use std::collections::HashMap;

/// A page has a body and a content-type.
struct Page {
    body: &'static [u8],
    content_type: &'static str,
}

lazy_static! {
    /// A HashMap of web paths to Pages.
    static ref FILES: HashMap<&'static str, Page> = {
        let mut f: HashMap<&'static str, Page> = HashMap::new();
        f.insert(
            "/favicon.ico",
            Page {
                body: include_bytes!("../static/favicon.ico"),
                content_type: "image/x-icon",
            },
        );
        f.insert(
            "/index.html",
            Page {
                body: include_bytes!("../static/index.html"),
                content_type: "text/html",
            },
        );
        f.insert(
            "/fastly.svg",
            Page {
                body: include_bytes!("../static/fastly.svg"),
                content_type: "image/svg+xml",
            },
        );
        f.insert(
            "/style.css",
            Page {
                body: include_bytes!("../static/style.css"),
                content_type: "text/css",
            },
        );
        f.insert(
            "/index.js",
            Page {
                body: include_bytes!("../static/index.js"),
                content_type: "application/javascript",
            },
        );
        f.insert(
            "/images/Captcha-On-Edge.png",
            Page {
                body: include_bytes!("../images/Captcha-On-Edge.png"),
                content_type: "image/png",
            },
        );
        f.insert(
            "/.well-known/fastly/demo-manifest",
            Page {
                body: include_bytes!("../.well-known/fastly/demo-manifest"),
                content_type: "application/octet-stream",
            },
        );
        f
    };
}

struct CaptchaConfig {
    secret_access_key: String,
}

impl CaptchaConfig {
    /// Load the the key.
    ///
    /// This assumes an Edge Dictionary named "captcha_config" is attached to this service,
    fn load_config() -> Self {
        let cfg = ConfigStore::open("captcha_config");
        Self {
            secret_access_key: cfg.get("secret_access_key").expect("secret configured"),
        }
    }
}

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    if req.get_path().ends_with('/') {
        req.set_path(&format!("{}index.html", req.get_path()));
    }

    println!(
        "Request received: {} {}",
        req.get_method_str(),
        req.get_path()
    );

    // Make any desired changes to the client request.
    // We can filter requests that have unexpected methods.
    const VALID_METHODS: [Method; 3] = [Method::HEAD, Method::GET, Method::POST];

    if !(VALID_METHODS.contains(req.get_method())) {
        return Ok(Response::new()
            .with_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_body(Body::from("This method is not allowed")));
    }

    let captcha_config = CaptchaConfig::load_config();
    let captcha_secret_string = captcha_config.secret_access_key.to_string().into_bytes();

    // Pattern match on the request method and path.

    match (req.get_method(), req.get_path()) {
        // If request is a `GET` to the `/` path, send a default response.
        (&Method::GET, path) if FILES.contains_key(path) => {
            if FILES[path].content_type.contains("image") {
                Ok(Response::new()
                    .with_status(StatusCode::OK)
                    .with_header("Cache-Control", "max-age=10")
                    .with_header("Content-Type", FILES[path].content_type)
                    .with_header("Access-Control-Allow-Origin", "*")
                    .with_body(FILES[path].body))
            } else {
                Ok(Response::new()
                    .with_status(StatusCode::OK)
                    .with_header("Cache-Control", "max-age=10")
                    .with_header("Content-Type", FILES[path].content_type)
                    .with_header("Access-Control-Allow-Origin", "*")
                    .with_header("X-Compress-Hint", "on")
                    .with_body(FILES[path].body))
            }
        }

        (&Method::GET, "/generateCaptcha") => {
            gen(Difficulty::Easy).as_png();
            let mut cap_tcha = Captcha::new();
            cap_tcha
                .add_chars(5)
                .apply_filter(Noise::new(0.1))
                .view(220, 80);
            let img_cap = cap_tcha.as_png().unwrap();

            let captcha_signature = &sign(
                &captcha_secret_string,
                cap_tcha.chars_as_string().as_bytes(),
            );

            Ok(Response::new()
                .with_status(StatusCode::OK)
                .with_header("Cache-Control", "max-age=600")
                .with_header("Access-Control-Allow-Origin", "*")
                .with_header("Content-Type", "image/png")
                .with_header("Custom-Header", "Fastly Captcha")
                .with_header(
                    "set-cookie",
                    format!(
                        "captcha-string={}; SameSite=None; Secure",
                        hex::encode(captcha_signature)
                    ),
                )
                .with_body(img_cap))
        }
        // If request is a `GET` to the `/backend` path, send to a named backend.
        (&Method::POST, "/verifyCaptcha") => {
            let body = req.take_body();

            let cookie_value: Option<&str> = {
                let c = Cookie::parse(
                    req.get_header_str("cookie")
                        .expect("no Cookie header provided"),
                )
                .unwrap();
                c.value_raw()
            };

            let body_hex = hex::encode(sign(&captcha_secret_string, body.into_bytes().as_slice()));

            if body_hex == cookie_value.unwrap() {
                Ok(Response::new().with_status(StatusCode::OK))
            } else {
                Ok(Response::new()
                    .with_status(StatusCode::NOT_ACCEPTABLE)
                    .with_header("captcha-string", body_hex))
            }
        }

        // Catch all other requests and return a 404.
        _ => Ok(Response::new()
            .with_status(StatusCode::NOT_FOUND)
            .with_body(Body::from("The page you requested could not be found"))),
    }
}

/// Generate HMAC hash of message with key
fn sign<'a>(key: &[u8], message: impl Into<&'a [u8]>) -> [u8; 32] {
    HMAC::mac(message.into(), key)
}
