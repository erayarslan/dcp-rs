#[path = "io/mod.rs"]
mod dcp_io;

use crate::dcp_io::client::Client;
use crate::dcp_io::consts::PacketCallback;
use crate::dcp_io::couchbase::Couchbase;
use std::net::TcpStream;
use std::sync::Arc;
use std::{io, thread};

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
    config: Arc<Config>,
    client: Arc<Client>,
}

impl Dcp {
    pub fn new(config: Config) -> io::Result<Self> {
        let tcp_stream = TcpStream::connect(config.hosts[0].as_str())?;
        let client: Client = Client::new(tcp_stream);

        Ok(Self {
            config: Arc::new(config),
            client: Arc::new(client),
        })
    }

    pub fn add_listener(&self, callback: PacketCallback) {
        self.client.add_listener(callback);
    }

    pub fn start(&self) -> io::Result<()> {
        let client = Arc::clone(&self.client);
        let config = Arc::clone(&self.config);

        thread::spawn(move || {
            let couchbase = Couchbase::new(&client);

            match couchbase.connect(&config) {
                Ok(..) => log::info!("stream started"),
                Err(e) => log::error!("stream cannot started: {}", e),
            }
        });

        self.client.start()
    }

    pub fn stop(&self) -> io::Result<()> {
        self.client.stop();
        Ok(())
    }
}
