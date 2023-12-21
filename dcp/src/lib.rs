#[path = "io/mod.rs"]
mod dcp_io;

use crate::dcp_io::client::Client;
use crate::dcp_io::couchbase::Couchbase;
use std::net::TcpStream;
use std::sync::Arc;
use std::{io, thread};
pub use crate::dcp_io::consts::ListenerCallback;

pub struct GroupConfig {
    pub name: String,
}

pub struct DcpConfig {
    pub group: GroupConfig,
}

pub struct Config {
    pub hosts: Vec<String>,
    pub username: String,
    pub password: String,
    pub bucket: String,
    pub scope_name: String,
    pub collection_names: Vec<String>,
    pub dcp: DcpConfig,
}

pub struct Dcp {
    config: Config,
    listener: ListenerCallback,
}

// todo: logger
impl Dcp {
    pub fn new(config: Config, listener: ListenerCallback) -> Self {
        Self { config, listener }
    }

    fn connect(&self, couchbase: &mut Couchbase, client: &Client) -> io::Result<()> {
        couchbase.send_hello()?;
        couchbase.sasl_list()?;
        couchbase.sasl_auth_continue_with_plain(
            self.config.username.as_str(),
            self.config.password.as_str(),
        )?;
        couchbase.select_bucket(self.config.bucket.as_str())?;
        for collection_name in &self.config.collection_names {
            couchbase.get_collection_id(self.config.scope_name.as_str(), collection_name.as_str())?;
        }
        couchbase.open_conn(self.config.dcp.group.name.as_str())?;
        couchbase.exec_noop()?;
        couchbase.enable_expiry_opcode()?;
        couchbase.open_stream()?;

        client.flush()?;

        Ok(())
    }

    pub fn start(self) -> io::Result<()> {
        match TcpStream::connect(self.config.hosts[0].as_str()) {
            Ok(tcp_stream) => {
                let client = Client::new(tcp_stream);
                let stream = Arc::new(client);
                let reader = Arc::clone(&stream);

                let shared_self = Arc::new(self);
                let self_copy = Arc::clone(&shared_self);

                thread::spawn(move || {
                    let mut couchbase = Couchbase::new(&stream);
                    match &shared_self.connect(&mut couchbase, &stream) {
                        Ok(..) => println!("stream started"),
                        Err(e) => println!("stream cannot started: {}", e),
                    }
                });

                match reader.listen(self_copy.listener) {
                    Ok(..) => println!("stream stopped"),
                    Err(e) => println!("cannot listen: {}", e),
                }
            }
            Err(e) => {
                println!("cannot connect: {}", e);
            }
        }

        Ok(())
    }
}
