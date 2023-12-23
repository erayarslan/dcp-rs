use crate::dcp_io::consts::PacketCallback;
use crate::dcp_io::packet::Packet;
use std::collections::HashMap;
use std::io;
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

pub struct Client {
    tcp_stream: Mutex<TcpStream>,
    opaque_map: Mutex<HashMap<u32, PacketCallback>>,
    running: AtomicBool,
    callback: Mutex<Option<PacketCallback>>,
    finished: AtomicBool,
}

impl Client {
    pub fn new(tcp_stream: TcpStream) -> Self {
        Client {
            tcp_stream: Mutex::new(tcp_stream),
            opaque_map: Mutex::new(HashMap::new()),
            running: AtomicBool::new(false),
            callback: Mutex::new(None),
            finished: AtomicBool::new(false),
        }
    }

    pub fn add_listener(&self, callback: PacketCallback) {
        let mut listener = self.callback.lock().unwrap();
        *listener = Some(callback)
    }

    pub(crate) fn send(&self, packet: &Packet) -> io::Result<()> {
        let buffer = packet.to_buffer()?;
        self.tcp_stream.lock().unwrap().write_all(&buffer)?;
        Ok(())
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        self.tcp_stream.lock().unwrap().flush()?;
        Ok(())
    }

    pub(crate) fn then(&self, packet: &Packet, callback: PacketCallback) -> io::Result<()> {
        let mut opaque_map = self.opaque_map.lock().unwrap();
        opaque_map.insert(packet.opaque, callback);

        Ok(())
    }

    pub fn start(&self) -> io::Result<()> {
        let tcp_stream = self.tcp_stream.lock().unwrap().try_clone()?;
        let mut reader: BufReader<&TcpStream> = BufReader::new(&tcp_stream);

        self.running.store(true, Ordering::Relaxed);
        while self.running.load(Ordering::Relaxed) {
            let packet = Packet::from_buffer(&mut reader);
            if packet.is_err() {
                self.running.store(false, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "failed to read packet",
                ));
            }

            let packet = packet.unwrap();
            log::debug!("packet command: {}", packet.command);

            if packet.status != 0 {
                self.running.store(false, Ordering::Relaxed);
                return Err(io::Error::new(io::ErrorKind::Other, "got error response"));
            }

            if self.opaque_map.lock().unwrap().contains_key(&packet.opaque) {
                let mut opaque_map = self.opaque_map.lock().unwrap();
                let mut opaque_callback = opaque_map.remove(&packet.opaque).unwrap();

                opaque_callback(&packet).expect("opaque callback got error");
            }

            if packet.command == 0x57 || packet.command == 0x58 || packet.command == 0x59 {
                let mut listener = self.callback.lock().unwrap();
                if let Some(callback) = &mut *listener {
                    callback(&packet).expect("listener got error");
                }
            }
        }

        self.finished.store(true, Ordering::Relaxed);

        Ok(())
    }

    pub fn stop(&self) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        self.running.store(false, Ordering::Relaxed);
        while !self.finished.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
