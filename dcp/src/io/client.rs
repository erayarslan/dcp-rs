use crate::dcp_io::consts::{ListenerCallback, PacketCallback};
use crate::dcp_io::packet::Packet;
use std::collections::HashMap;
use std::io;
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;

pub struct Client {
    tcp_stream: Mutex<TcpStream>,
    opaque_map: Mutex<HashMap<u32, PacketCallback>>,
}

impl Client {
    pub fn new(tcp_stream: TcpStream) -> Self {
        Client {
            tcp_stream: Mutex::new(tcp_stream),
            opaque_map: Mutex::new(HashMap::new()),
        }
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

    pub fn listen(&self, callback: ListenerCallback) -> io::Result<()> {
        let tcp_stream = self.tcp_stream.lock().unwrap().try_clone()?;
        let mut reader: BufReader<&TcpStream> = BufReader::new(&tcp_stream);

        loop {
            let packet = Packet::from_buffer(&mut reader)?;

            if packet.status != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "got error response"));
            }

            if self.opaque_map.lock().unwrap().contains_key(&packet.opaque) {
                let mut opaque_map = self.opaque_map.lock().unwrap();
                let callback = opaque_map.remove(&packet.opaque).unwrap();

                callback(&packet);
            }

            if packet.command == 0x57 || packet.command == 0x58 || packet.command == 0x59 {
                callback(&packet);
            }
        }
    }
}
