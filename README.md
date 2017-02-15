# trytls-openssl

This uses trytls with [hyper](https://github.com/hyperium/hyper) and [openssl](https://github.com/sfackler/rust-openssl/). Compare to results from [rustls](https://github.com/avadacatavra/trytls-rustls-stub)

To run:

1. Install [trytls](https://github.com/ouspg/trytls)
2. trytls https cargo run --quiet

Current results:
*  FAIL denies use of MD5 signature algorithm (RFC 6151) [reject weak-sig.badtls.io:11004]
*  FAIL use only the given CA bundle, not system's [reject sha256.badssl.com:443]

Both failures are probably fixable, but that's a TODO
