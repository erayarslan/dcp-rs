use crate::dcp_io::consts::{
    is_command_collection_enabled, CmdCode, CmdMagic, StatusCode, CMD_MAGIC_REQ, CMD_MAGIC_REQ_EXT,
    CMD_MAGIC_RES, CMD_MAGIC_RES_EXT, CMD_MAGIC_SERVER_REQ, FEATURE_MAP, OPAQUE,
};
use crate::dcp_io::utils::{
    append_uleb128_32, calc_header_size, decode_uleb128_32, write_frame_header,
};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::fmt::{Display, Formatter};
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

pub struct BarrierFrame {}

pub struct DurabilityLevelFrame {
    durability_level: u8,
}

pub struct DurabilityTimeoutFrame {
    durability_timeout: i64,
}

pub struct StreamIdFrame {
    stream_id: u16,
}

pub struct OpenTracingFrame {
    trace_context: Vec<u8>,
}

pub struct UserImpersonationFrame {
    user: Vec<u8>,
}

pub struct PreserveExpiryFrame {}

#[allow(dead_code)]
pub struct ReadUnitsFrame {
    read_units: u16,
}

#[allow(dead_code)]
pub struct WriteUnitsFrame {
    write_units: u16,
}

pub struct UnsupportedFrame {
    frame_type: u8,
    frame_body: Vec<u8>,
}

pub struct ServerDurationFrame {
    server_duration: i64,
}

pub struct Packet {
    pub(crate) magic: CmdMagic,
    pub(crate) command: CmdCode,
    pub(crate) datatype: u8,
    pub(crate) status: StatusCode,
    pub(crate) v_bucket: u16,
    pub(crate) opaque: u32,
    pub(crate) cas: u64,
    pub(crate) collection_id: u32,
    pub(crate) key: Vec<u8>,
    pub(crate) extras: Vec<u8>,
    pub(crate) value: Vec<u8>,

    pub(crate) barrier_frame: Option<BarrierFrame>,
    pub(crate) durability_level_frame: Option<DurabilityLevelFrame>,
    pub(crate) durability_timeout_frame: Option<DurabilityTimeoutFrame>,
    pub(crate) stream_id_frame: Option<StreamIdFrame>,
    pub(crate) open_tracing_frame: Option<OpenTracingFrame>,
    pub(crate) server_duration_frame: Option<ServerDurationFrame>,
    pub(crate) user_impersonation_frame: Option<UserImpersonationFrame>,
    pub(crate) preserve_expiry_frame: Option<PreserveExpiryFrame>,
    pub(crate) read_units_frame: Option<ReadUnitsFrame>,
    pub(crate) write_units_frame: Option<WriteUnitsFrame>,
    pub(crate) unsupported_frame: Vec<UnsupportedFrame>,
}

impl Display for Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let key = String::from_utf8_lossy(&self.key);
        let value = String::from_utf8_lossy(&self.value);

        write!(f, "Packet {{ magic: {:04}, command: {:04}, status: {:02}, v_bucket: {:04}, key: {}, value: {} }}",
               self.magic,
               self.command,
               self.status,
               self.v_bucket,
               key,
               value,
        )
    }
}

impl Default for Packet {
    fn default() -> Self {
        let pck_opaque = *OPAQUE.lock().unwrap();
        let mut opaque = OPAQUE.lock().unwrap();
        *opaque += 1;

        Packet {
            magic: 0,
            command: 0,
            datatype: 0,
            status: 0,
            v_bucket: 0,
            opaque: pck_opaque,
            cas: 0,
            collection_id: 0,
            key: vec![],
            extras: vec![],
            value: vec![],
            barrier_frame: None,
            durability_level_frame: None,
            durability_timeout_frame: None,
            stream_id_frame: None,
            open_tracing_frame: None,
            server_duration_frame: None,
            user_impersonation_frame: None,
            preserve_expiry_frame: None,
            read_units_frame: None,
            write_units_frame: None,
            unsupported_frame: vec![],
        }
    }
}

impl Packet {
    pub fn from_buffer(reader: &mut BufReader<&TcpStream>) -> io::Result<Self> {
        let mut packet: Packet = Default::default();

        let mut header_buf = [0u8; 24];
        reader.read_exact(&mut header_buf)?;
        let body_len = BigEndian::read_u32(&mut header_buf[8..]);
        let mut body_buf = vec![0u8; body_len as usize];
        reader.read_exact(&mut body_buf)?;

        let pkt_magic: CmdMagic = header_buf[0];

        if pkt_magic == CMD_MAGIC_REQ || pkt_magic == CMD_MAGIC_REQ_EXT {
            packet.magic = CMD_MAGIC_REQ;
            packet.v_bucket = BigEndian::read_u16(&mut header_buf[6..]);
        } else if pkt_magic == CMD_MAGIC_RES || pkt_magic == CMD_MAGIC_RES_EXT {
            packet.magic = CMD_MAGIC_RES;
            packet.status = BigEndian::read_u16(&mut header_buf[6..]);
        } else if pkt_magic == CMD_MAGIC_SERVER_REQ {
            packet.magic = CMD_MAGIC_SERVER_REQ;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot decode status/vbucket for unknown packet magic",
            ));
        }

        packet.command = header_buf[1];
        packet.datatype = header_buf[5];
        packet.opaque = BigEndian::read_u32(&mut header_buf[12..]);
        packet.cas = BigEndian::read_u64(&mut header_buf[16..]);

        let ext_len = header_buf[4];
        let mut key_len = BigEndian::read_u16(&mut header_buf[2..]) as i32;
        let mut frames_len: usize = 0;

        if pkt_magic == CMD_MAGIC_REQ_EXT || pkt_magic == CMD_MAGIC_RES_EXT {
            frames_len = header_buf[2] as usize;
            key_len = header_buf[3] as i32;
        }

        if frames_len > 0 {
            let frames_buf = vec![0u8; frames_len];
            body_buf[..frames_len].clone_from_slice(&frames_buf[..frames_len]);
            let mut frame_pos = 0;

            while frame_pos < frames_len {
                let frame_header = frames_buf[frame_pos];
                frame_pos += 1;

                let mut frame_type = (frame_header & 0xF0) >> 4;
                if frame_type == 15 {
                    frame_type = 15 + frames_buf[frame_pos];
                    frame_pos += 1;
                }

                let mut frame_len = ((frame_header & 0x0F) >> 0) as usize;
                if frame_len == 15 {
                    frame_len = (15 + frames_buf[frame_pos]) as usize;
                    frame_pos += 1;
                }

                let mut frame_body = vec![0u8; frame_len];
                frame_body[..frame_len]
                    .clone_from_slice(&frames_buf[frame_pos..frame_pos + frame_len]);
                frame_pos += frame_len;

                if pkt_magic == CMD_MAGIC_REQ_EXT {
                    if frame_type == 0 && frame_len == 0 {
                        packet.barrier_frame = Option::from(BarrierFrame {});
                    } else if frame_type == 1 && (frame_len == 1 || frame_len == 3) {
                        packet.durability_level_frame = Option::from(DurabilityLevelFrame {
                            durability_level: frame_body[0],
                        });
                        if frame_len == 3 {
                            packet.durability_timeout_frame =
                                Option::from(DurabilityTimeoutFrame {
                                    durability_timeout: BigEndian::read_u16(&frame_body[1..])
                                        as i64,
                                });
                        } else {
                            packet.durability_timeout_frame =
                                Option::from(DurabilityTimeoutFrame {
                                    durability_timeout: 0,
                                });
                        }
                    } else if frame_type == 2 && frame_len == 2 {
                        packet.stream_id_frame = Option::from(StreamIdFrame {
                            stream_id: BigEndian::read_u16(&*frame_body),
                        });
                    } else if frame_type == 3 {
                        packet.open_tracing_frame = Option::from(OpenTracingFrame {
                            trace_context: frame_body,
                        });
                    } else if frame_type == 5 {
                        packet.preserve_expiry_frame = Option::from(PreserveExpiryFrame {});
                    } else if frame_type == 4 {
                        packet.user_impersonation_frame =
                            Option::from(UserImpersonationFrame { user: frame_body });
                    } else {
                        packet.unsupported_frame.push(UnsupportedFrame {
                            frame_type,
                            frame_body,
                        });
                    }
                } else if pkt_magic == CMD_MAGIC_RES_EXT {
                    if frame_type == 0 && frame_len == 2 {
                        packet.server_duration_frame = Option::from(ServerDurationFrame {
                            server_duration: BigEndian::read_u16(&*frame_body) as i64,
                        });
                    } else if frame_type == 1 && frame_len == 2 {
                        packet.read_units_frame = Option::from(ReadUnitsFrame {
                            read_units: BigEndian::read_u16(&*frame_body),
                        });
                    } else if frame_type == 2 && frame_len == 2 {
                        packet.write_units_frame = Option::from(WriteUnitsFrame {
                            write_units: BigEndian::read_u16(&*frame_body),
                        });
                    } else {
                        packet.unsupported_frame.push(UnsupportedFrame {
                            frame_type,
                            frame_body,
                        });
                    }
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "got unexpected magic when decoding frames",
                    ));
                }
            }
        }

        packet.extras = Vec::from(&body_buf[frames_len..frames_len + ext_len as usize]);
        packet.key = Vec::from(
            &body_buf
                [frames_len + ext_len as usize..frames_len + ext_len as usize + key_len as usize],
        );
        packet.value = Vec::from(&body_buf[frames_len + ext_len as usize + key_len as usize..]);

        if FEATURE_MAP.lock().unwrap().contains_key(&0x12) {
            if packet.command == 0x92 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "the observe operation is not supported with collections enabled",
                ));
            }

            if key_len > 0 && is_command_collection_enabled(packet.command) {
                let (cid, id_len) = decode_uleb128_32(packet.key.as_slice())?;
                packet.collection_id = cid;
                packet.key = packet.key[id_len..].to_vec();
            }
        }

        Ok(packet)
    }

    pub(crate) fn to_buffer(&self) -> io::Result<Vec<u8>> {
        let mut encoded_key: Vec<u8> = self.key.clone();
        let extras = &self.extras;

        if FEATURE_MAP.lock().unwrap().contains_key(&0x12) {
            if self.command == 0x92 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "the observe operation is not supported with collections enabled",
                ));
            }

            if is_command_collection_enabled(self.command) {
                let mut collection_encoded_key = vec![0u8; encoded_key.len() + 5];
                append_uleb128_32(&mut collection_encoded_key, self.collection_id);
                collection_encoded_key.extend_from_slice(&*encoded_key);
                encoded_key = collection_encoded_key;
            } else if self.command == 0xb6 {
                let mut extras = vec![0u8; 4];
                extras.write_u32::<BigEndian>(self.collection_id)?;
            } else {
                if self.collection_id > 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "cannot encode collection id with a non-collection command",
                    ));
                }
            }
        } else {
            if self.collection_id > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot encode collection id without the feature enabled",
                ));
            }
        }

        let ext_len = extras.len();
        let key_len = encoded_key.len();
        let val_len = self.value.len();

        let mut frames_len = 0;
        if self.barrier_frame.is_some() {
            frames_len += 1;
        }
        if self.durability_level_frame.is_some() {
            if self.durability_timeout_frame.is_some() {
                frames_len += 2;
            } else {
                frames_len += 4;
            }
        }
        if self.stream_id_frame.is_some() {
            frames_len += 3;
        }
        if self.open_tracing_frame.is_some() {
            frames_len += calc_header_size(
                self.open_tracing_frame
                    .as_ref()
                    .unwrap()
                    .trace_context
                    .len(),
            );
        }
        if self.server_duration_frame.is_some() {
            frames_len += 3;
        }
        if self.user_impersonation_frame.is_some() {
            frames_len +=
                calc_header_size(self.user_impersonation_frame.as_ref().unwrap().user.len());
        }
        if self.preserve_expiry_frame.is_some() {
            frames_len += 1;
        }
        for frame in self.unsupported_frame.iter() {
            frames_len += calc_header_size(frame.frame_body.len());
        }

        let mut pkt_magic = self.magic;
        if frames_len > 0 {
            match pkt_magic {
                0x80 => {
                    if !FEATURE_MAP.lock().unwrap().contains_key(&0x10) {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "cannot use frames in req packets without enabling the feature",
                        ));
                    }

                    pkt_magic = CMD_MAGIC_REQ_EXT;
                }
                0x81 => {
                    pkt_magic = CMD_MAGIC_RES_EXT;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "cannot use frames with an unsupported magic",
                    ));
                }
            }
        }

        let mut buffer = vec![0u8; 0];
        buffer.write_u8(pkt_magic)?;
        buffer.write_u8(self.command)?;

        if frames_len > 0 {
            buffer.write_u8(frames_len as u8)?;
            buffer.write_u8(key_len as u8)?;
        } else {
            buffer.write_u16::<BigEndian>(key_len as u16)?;
        }

        buffer.write_u8(ext_len as u8)?;
        buffer.write_u8(self.datatype)?;

        match self.magic {
            0x80 => {
                if self.status != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "cannot specify status in a request packet",
                    ));
                }

                buffer.write_u16::<BigEndian>(self.v_bucket)?;
            }
            0x81 => {
                if self.v_bucket != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "cannot specify vbucket in a response packet",
                    ));
                }

                buffer.write_u16::<BigEndian>(self.status)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot encode status/vbucket for unknown packet magic",
                ));
            }
        }

        buffer.write_u32::<BigEndian>((key_len + ext_len + val_len + frames_len) as u32)?;
        buffer.write_u32::<BigEndian>(self.opaque)?;
        buffer.write_u64::<BigEndian>(self.cas)?;

        if self.barrier_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use barrier frame in non-request packets",
                ));
            }

            write_frame_header(&mut buffer, 0, 0)?;
        }

        if self.durability_level_frame.is_some() || self.durability_timeout_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use durability level frame in non-request packets",
                ));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x11) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use sync replication frames without enabling the feature",
                ));
            }

            if self.durability_level_frame.is_none() && self.durability_timeout_frame.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot encode durability timeout frame without durability level frame",
                ));
            }

            if self.durability_timeout_frame.is_none() {
                write_frame_header(&mut buffer, 1, 1)?;
                buffer.write_u8(
                    self.durability_level_frame
                        .as_ref()
                        .unwrap()
                        .durability_level,
                )?;
            } else {
                write_frame_header(&mut buffer, 1, 3)?;
                buffer.write_u8(
                    self.durability_level_frame
                        .as_ref()
                        .unwrap()
                        .durability_level,
                )?;
                buffer.write_u16::<BigEndian>(
                    self.durability_timeout_frame
                        .as_ref()
                        .unwrap()
                        .durability_timeout as u16,
                )?;
            }
        }

        if self.stream_id_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use stream id frame in non-request packets",
                ));
            }

            write_frame_header(&mut buffer, 2, 2)?;
            buffer.write_u16::<BigEndian>(self.stream_id_frame.as_ref().unwrap().stream_id)?;
        }

        if self.open_tracing_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use open tracing frame in non-request packets",
                ));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x13) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use open tracing frames without enabling the feature",
                ));
            }

            let trace_ctx_len = self
                .open_tracing_frame
                .as_ref()
                .unwrap()
                .trace_context
                .len();
            write_frame_header(&mut buffer, 3, trace_ctx_len as u8)?;
            buffer.write(&self.open_tracing_frame.as_ref().unwrap().trace_context)?;
        }

        if self.server_duration_frame.is_some() {
            if self.magic != CMD_MAGIC_RES {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use server duration frame in non-response packets",
                ));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0xf) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use server duration frames without enabling the feature",
                ));
            }

            write_frame_header(&mut buffer, 0, 2)?;
            buffer.write_u16::<BigEndian>(
                self.server_duration_frame.as_ref().unwrap().server_duration as u16,
            )?;
        }

        if self.user_impersonation_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use user impersonation frame in non-request packets",
                ));
            }

            let user_ctx_len = self.user_impersonation_frame.as_ref().unwrap().user.len();
            write_frame_header(&mut buffer, 4, user_ctx_len as u8)?;
            buffer.write(&self.user_impersonation_frame.as_ref().unwrap().user)?;
        }

        if self.preserve_expiry_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use preserve expiry frame in non-request packets",
                ));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x14) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot use preserve expiry frames without enabling the feature",
                ));
            }

            write_frame_header(&mut buffer, 5, 0)?;
        }

        for frame in self.unsupported_frame.iter() {
            write_frame_header(&mut buffer, frame.frame_type, frame.frame_body.len() as u8)?;
            buffer.write(&frame.frame_body)?;
        }

        buffer.write(extras)?;
        buffer.write(&encoded_key)?;
        buffer.write(&self.value)?;

        Ok(buffer)
    }
}
