# dcp-rs

This repository contains Rust implementation of a Couchbase Database Change Protocol (DCP)

### Contents

* [Example](#example)

### Example

```rust
use dcp_rs::{Config, Dcp, DcpConfig, GroupConfig};

fn main() -> Result<(), std::io::Error> {
    let config = Config {
        hosts: vec!["localhost:11210".to_string()],
        username: "user".to_string(),
        password: "123456".to_string(),
        bucket: "dcp-test".to_string(),
        scope_name: "_default".to_string(),
        collection_names: vec!["_default".to_string()],
        dcp: DcpConfig {
            group: GroupConfig {
                name: "group_name".to_string(),
            },
        },
    };

    let dcp = Dcp::new(config)?;
    dcp.add_listener(Box::new(|event| {
        println!("event: {}", event);

        Ok(())
    }));
    dcp.start()?;

    return Ok(());
}
```