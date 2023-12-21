use crate::dcp_io::client::Client;
use crate::dcp_io::consts::FEATURE_MAP;
use crate::dcp_io::packet::Packet;
use crate::dcp_io::utils::{format_cb_uid, random_cb_uid};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::io;
use std::io::Write;
use std::sync::Mutex;

pub struct Couchbase<'a> {
    client: Mutex<&'a Client>,
}

impl Couchbase<'_> {
    pub fn new(client: &Client) -> Couchbase {
        Couchbase {
            client: Mutex::new(client),
        }
    }

    pub(crate) fn send_hello(&mut self) -> io::Result<()> {
        let futures: Vec<u16> = vec![
            2, 6, 8, 30, 29, 12, 7, 11, 10, 19, 18, 16, 23, 25, 20, 28, 17,
        ];
        let mut futures_value = vec![0u8; 0];
        for future in futures.iter() {
            futures_value.write_u16::<BigEndian>(*future)?;
        }

        let packet = Packet {
            magic: 128,
            command: 31,
            key: format!(
                "{{\"a\":\"dcp-rs/v0.0.1\",\"i\":\"{}/{}\"}}",
                format_cb_uid(random_cb_uid()),
                format_cb_uid(random_cb_uid())
            )
            .as_bytes()
            .to_vec(),
            value: futures_value,
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;
        client.then(&packet, |packet| {
            let mut i = 0;

            while i < packet.value.len() {
                let feature = BigEndian::read_u16(&packet.value[i..]);
                let mut feature_map = FEATURE_MAP.lock().unwrap();
                feature_map.insert(feature, true);
                i += 2;
            }
        })?;

        Ok(())
    }

    pub(crate) fn sasl_list(&mut self) -> io::Result<()> {
        let packet = Packet {
            magic: 128,
            command: 32,
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn sasl_auth_continue_with_plain(
        &mut self,
        username: &str,
        password: &str,
    ) -> io::Result<()> {
        let mut user_pass = vec![0u8; 0];
        user_pass.write_u8(0)?;
        user_pass.write(username.as_bytes())?;
        user_pass.write_u8(0)?;
        user_pass.write(password.as_bytes())?;

        let packet = Packet {
            magic: 128,
            command: 33,
            key: "PLAIN".as_bytes().to_vec(),
            value: user_pass,
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn select_bucket(&mut self, bucket_name: &str) -> io::Result<()> {
        let packet = Packet {
            magic: 128,
            command: 137,
            key: bucket_name.as_bytes().to_vec(),
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn open_conn(&mut self, group_name: &str) -> io::Result<()> {
        let packet = Packet {
            magic: 128,
            command: 80,
            key: group_name.as_bytes().to_vec(),
            extras: vec![0, 0, 0, 0, 0, 0, 0, 1],
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn exec_noop(&mut self) -> io::Result<()> {
        let packet = Packet {
            magic: 128,
            command: 94,
            key: "enable_noop".as_bytes().to_vec(),
            value: "true".as_bytes().to_vec(),
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn enable_expiry_opcode(&mut self) -> io::Result<()> {
        let packet = Packet {
            magic: 128,
            command: 94,
            key: "enable_expiry_opcode".as_bytes().to_vec(),
            value: "true".as_bytes().to_vec(),
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;

        Ok(())
    }

    pub(crate) fn open_stream(&mut self) -> io::Result<()> {
        let client = self.client.lock().unwrap();

        for i in 0..1024 {
            let packet = Packet {
                magic: 128,
                command: 83,
                v_bucket: i,
                extras: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
                    255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,
                ],
                value: "{\"uid\":\"0\",\"collections\":[\"0\"]}"
                    .as_bytes()
                    .to_vec(), // todo: fill with real data
                ..Default::default()
            };

            client.send(&packet)?;
        }

        Ok(())
    }

    pub(crate) fn get_collection_id(
        &mut self,
        scope_name: &str,
        collection_name: &str,
    ) -> io::Result<u32> {
        let packet = Packet {
            magic: 128,
            command: 187,
            value: format!("{}.{}", scope_name, collection_name)
                .as_bytes()
                .to_vec(),
            ..Default::default()
        };

        let client = self.client.lock().unwrap();
        client.send(&packet)?;
        client.then(&packet, |packet| {
            let collection_id = BigEndian::read_u32(&packet.extras[8..]);
            println!("collection id: {}", collection_id)
        })?;

        Ok(0)
    }
}
