# rfc7239

Parser for [rfc7239] formatted `Forwarded` headers.

## Usage

```rust
use rfc7239::parse;

// get the header value from your favorite http server library
let header_value = "for=192.0.2.60;proto=http;by=203.0.113.43,for=192.168.10.10";

for node_result in parse(header_value) {
    let node = node_result?;
    if let Some(forwarded_for) = node.forwarded_for {
        println!("Forwarded by {}", forwarded_for)
    }
}
```

[rfc7239]: https://tools.ietf.org/html/rfc7239