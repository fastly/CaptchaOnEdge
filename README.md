This is a Rust app that generates a captcha and saves a signed token in a cookie which is used to verify the captcha when it is resolved. If you enter a wrong string and submit, you will be presented with a new captcha string to solve. Once you solve the cqptcha string and if it verifies accurately the screen will refresh after 4s.

Built with external Rust crates: captcha, lazy_static, hmac_sha256, cookie, hex, and http

When you initially load the https://captcha.edgecompute.app/ app, it loads an HTML+Javascript web app that are statically loaded from the RUST app into your client. The client app makes calls to various endpoints in the RUST app https://captcha.edgecompute.app/ from within and these endpoints each have a route within the Rust app that serves the request without the overhead of maintaining an origin server.

The app is completely stateless and origin-less i.e. it runs entirely on Fastly's Compute platform.

