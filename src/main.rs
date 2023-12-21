use std::{io, thread};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::BufReader;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use lazy_static::lazy_static;

type CmdMagic = u8;

static CMD_MAGIC_REQ: CmdMagic = 0x80;
static CMD_MAGIC_RES: CmdMagic = 0x81;
static CMD_MAGIC_SERVER_REQ: CmdMagic = 0x82;
static CMD_MAGIC_REQ_EXT: CmdMagic = 0x08;
static CMD_MAGIC_RES_EXT: CmdMagic = 0x18;

type CmdCode = u8;
type StatusCode = u16;

static COLLECTION_ID_SUPPORTED_OPS: [i32; 34] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0e,
    0x0f, 0x1c, 0x1d, 0x83, 0x94, 0x95, 0xa0, 0xa2,
    0xa8, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
    0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0x57,
    0x59, 0x58
];

fn make_cid_supported_table() -> Box<[u8]> {
    let mut cid_table_len: u32 = 0;
    for cmd in COLLECTION_ID_SUPPORTED_OPS.iter() {
        if *cmd as u32 >= cid_table_len {
            cid_table_len = (cmd + 1) as u32;
        }
    }

    let mut cid_table = vec![0u8; cid_table_len as usize];
    for cmd in COLLECTION_ID_SUPPORTED_OPS.iter() {
        cid_table[*cmd as usize] = 1;
    }

    cid_table.into_boxed_slice()
}

lazy_static! {
    static ref COLLECTION_ID_SUPPORTED_TABLE:Box<[u8]> = {
        make_cid_supported_table()
    };

    static ref OPAQUE: Mutex<u32> = Mutex::new(0);

    static ref OPAQUE_MAP: Mutex<HashMap<u32, PacketCallback>> = Mutex::new(HashMap::new());

    static ref FEATURE_MAP: Mutex<HashMap<u16, bool>> = Mutex::new(HashMap::new());
}

fn append_uleb128_32(b: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut c = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            c |= 0x80;
        }
        b.push(c);
        if c & 0x80 == 0 {
            break;
        }
    }
}

fn decode_uleb128_32(b: &[u8]) -> io::Result<(u32, usize)> {
    if b.len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "no data provided"));
    }

    let mut u: u64 = 0;
    let mut n: usize = 0;
    let i: usize = 0;

    loop {
        if i >= b.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "encoded number is longer than provided data"));
        }
        if i * 7 > 32 {
            u = 0xffffffffffffffff;
            break;
        }

        u |= ((b[i] & 0x7f) as u64) << (i * 7);

        if b[i] & 0x80 == 0 {
            n = i + 1;
            break;
        }
    }

    if u > 0xffffffff {
        return Err(io::Error::new(io::ErrorKind::Other, "encoded data is longer than 32 bits"));
    }

    Ok((u as u32, n))
}

fn write_frame_header(buffer: &mut Vec<u8>, frame_type: u8, frame_len: u8) -> io::Result<()> {
    if frame_len < 15 {
        buffer.write_u8((frame_type << 4) | frame_len)?;
        return Ok(());
    }

    buffer.write_u8((frame_type << 4) | 15)?;
    buffer.write_u8(frame_len - 15)?;
    Ok(())
}

fn random_cb_uid() -> Vec<u8> {
    let mut out = vec![0u8; 8];
    for i in 0..8 {
        out[i] = rand::random::<u8>();
    }

    out
}

fn format_cb_uid(data: Vec<u8>) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7])
}

fn calc_header_size(frame_len: usize) -> usize {
    if frame_len < 15 {
        return 1 + frame_len;
    }

    return 2 + frame_len;
}

fn is_command_collection_enabled(cmd: u8) -> bool {
    let cmd_idx = cmd as i32;
    if cmd_idx < 0 || cmd >= COLLECTION_ID_SUPPORTED_TABLE.len() as u8 {
        return false;
    }

    return COLLECTION_ID_SUPPORTED_TABLE[cmd as usize] == 1;
}

struct BarrierFrame {}

struct DurabilityLevelFrame {
    durability_level: u8,
}

struct DurabilityTimeoutFrame {
    durability_timeout: i64,
}

struct StreamIdFrame {
    stream_id: u16,
}

struct OpenTracingFrame {
    trace_context: Vec<u8>,
}

struct UserImpersonationFrame {
    user: Vec<u8>,
}

struct PreserveExpiryFrame {}

#[allow(dead_code)]
struct ReadUnitsFrame {
    read_units: u16,
}

#[allow(dead_code)]
struct WriteUnitsFrame {
    write_units: u16,
}

struct UnsupportedFrame {
    frame_type: u8,
    frame_body: Vec<u8>,
}

struct ServerDurationFrame {
    server_duration: i64,
}

type PacketCallback = fn(&Packet);
type ListenerCallback = fn(&Packet);

pub struct Packet {
    magic: CmdMagic,
    command: CmdCode,
    datatype: u8,
    status: StatusCode,
    v_bucket: u16,
    opaque: u32,
    cas: u64,
    collection_id: u32,
    key: Vec<u8>,
    extras: Vec<u8>,
    value: Vec<u8>,

    barrier_frame: Option<BarrierFrame>,
    durability_level_frame: Option<DurabilityLevelFrame>,
    durability_timeout_frame: Option<DurabilityTimeoutFrame>,
    stream_id_frame: Option<StreamIdFrame>,
    open_tracing_frame: Option<OpenTracingFrame>,
    server_duration_frame: Option<ServerDurationFrame>,
    user_impersonation_frame: Option<UserImpersonationFrame>,
    preserve_expiry_frame: Option<PreserveExpiryFrame>,
    read_units_frame: Option<ReadUnitsFrame>,
    write_units_frame: Option<WriteUnitsFrame>,
    unsupported_frame: Vec<UnsupportedFrame>,

    pub callback: Option<PacketCallback>,
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
        Packet {
            magic: 0,
            command: 0,
            datatype: 0,
            status: 0,
            v_bucket: 0,
            opaque: 0,
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
            callback: None,
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
            return Err(io::Error::new(io::ErrorKind::Other, "cannot decode status/vbucket for unknown packet magic"));
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
                frame_body[..frame_len].clone_from_slice(&frames_buf[frame_pos..frame_pos + frame_len]);
                frame_pos += frame_len;

                if pkt_magic == CMD_MAGIC_REQ_EXT {
                    if frame_type == 0 && frame_len == 0 {
                        packet.barrier_frame = Option::from(BarrierFrame {});
                    } else if frame_type == 1 && (frame_len == 1 || frame_len == 3) {
                        packet.durability_level_frame = Option::from(DurabilityLevelFrame {
                            durability_level: frame_body[0]
                        });
                        if frame_len == 3 {
                            packet.durability_timeout_frame = Option::from(DurabilityTimeoutFrame {
                                durability_timeout: BigEndian::read_u16(&frame_body[1..]) as i64
                            });
                        } else {
                            packet.durability_timeout_frame = Option::from(DurabilityTimeoutFrame {
                                durability_timeout: 0
                            });
                        }
                    } else if frame_type == 2 && frame_len == 2 {
                        packet.stream_id_frame = Option::from(StreamIdFrame {
                            stream_id: BigEndian::read_u16(&*frame_body)
                        });
                    } else if frame_type == 3 {
                        packet.open_tracing_frame = Option::from(OpenTracingFrame {
                            trace_context: frame_body
                        });
                    } else if frame_type == 5 {
                        packet.preserve_expiry_frame = Option::from(PreserveExpiryFrame {});
                    } else if frame_type == 4 {
                        packet.user_impersonation_frame = Option::from(UserImpersonationFrame {
                            user: frame_body
                        });
                    } else {
                        packet.unsupported_frame.push(UnsupportedFrame {
                            frame_type,
                            frame_body,
                        });
                    }
                } else if pkt_magic == CMD_MAGIC_RES_EXT {
                    if frame_type == 0 && frame_len == 2 {
                        packet.server_duration_frame = Option::from(ServerDurationFrame {
                            server_duration: BigEndian::read_u16(&*frame_body) as i64
                        });
                    } else if frame_type == 1 && frame_len == 2 {
                        packet.read_units_frame = Option::from(ReadUnitsFrame {
                            read_units: BigEndian::read_u16(&*frame_body)
                        });
                    } else if frame_type == 2 && frame_len == 2 {
                        packet.write_units_frame = Option::from(WriteUnitsFrame {
                            write_units: BigEndian::read_u16(&*frame_body)
                        });
                    } else {
                        packet.unsupported_frame.push(UnsupportedFrame {
                            frame_type,
                            frame_body,
                        });
                    }
                } else {
                    return Err(io::Error::new(io::ErrorKind::Other, "got unexpected magic when decoding frames"));
                }
            }
        }

        packet.extras = Vec::from(&body_buf[frames_len..frames_len + ext_len as usize]);
        packet.key = Vec::from(&body_buf[frames_len + ext_len as usize..frames_len + ext_len as usize + key_len as usize]);
        packet.value = Vec::from(&body_buf[frames_len + ext_len as usize + key_len as usize..]);

        if FEATURE_MAP.lock().unwrap().contains_key(&0x12) {
            if packet.command == 0x92 {
                return Err(io::Error::new(io::ErrorKind::Other, "the observe operation is not supported with collections enabled"));
            }

            if key_len > 0 && is_command_collection_enabled(packet.command) {
                let (cid, id_len) = decode_uleb128_32(packet.key.as_slice())?;
                packet.collection_id = cid;
                packet.key = packet.key[id_len..].to_vec();
            }
        }

        Ok(packet)
    }

    fn to_buffer(&self) -> io::Result<Vec<u8>> {
        let mut encoded_key: Vec<u8> = self.key.clone();
        let extras = &self.extras;

        if FEATURE_MAP.lock().unwrap().contains_key(&0x12) {
            if self.command == 0x92 {
                return Err(io::Error::new(io::ErrorKind::Other, "the observe operation is not supported with collections enabled"));
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
                    return Err(io::Error::new(io::ErrorKind::Other, "cannot encode collection id with a non-collection command"));
                }
            }
        } else {
            if self.collection_id > 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot encode collection id without the feature enabled"));
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
            frames_len += calc_header_size(self.open_tracing_frame.as_ref().unwrap().trace_context.len());
        }
        if self.server_duration_frame.is_some() {
            frames_len += 3;
        }
        if self.user_impersonation_frame.is_some() {
            frames_len += calc_header_size(self.user_impersonation_frame.as_ref().unwrap().user.len());
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
                        return Err(io::Error::new(io::ErrorKind::Other, "cannot use frames in req packets without enabling the feature"));
                    }

                    pkt_magic = CMD_MAGIC_REQ_EXT;
                }
                0x81 => {
                    pkt_magic = CMD_MAGIC_RES_EXT;
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "cannot use frames with an unsupported magic"));
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
                    return Err(io::Error::new(io::ErrorKind::Other, "cannot specify status in a request packet"));
                }

                buffer.write_u16::<BigEndian>(self.v_bucket)?;
            }
            0x81 => {
                if self.v_bucket != 0 {
                    return Err(io::Error::new(io::ErrorKind::Other, "cannot specify vbucket in a response packet"));
                }

                buffer.write_u16::<BigEndian>(self.status)?;
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot encode status/vbucket for unknown packet magic"));
            }
        }

        buffer.write_u32::<BigEndian>((key_len + ext_len + val_len + frames_len) as u32)?;
        buffer.write_u32::<BigEndian>(self.opaque)?;
        buffer.write_u64::<BigEndian>(self.cas)?;

        if self.barrier_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use barrier frame in non-request packets"));
            }

            write_frame_header(&mut buffer, 0, 0)?;
        }

        if self.durability_level_frame.is_some() || self.durability_timeout_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use durability level frame in non-request packets"));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x11) {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use sync replication frames without enabling the feature"));
            }

            if self.durability_level_frame.is_none() && self.durability_timeout_frame.is_some() {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot encode durability timeout frame without durability level frame"));
            }

            if self.durability_timeout_frame.is_none() {
                write_frame_header(&mut buffer, 1, 1)?;
                buffer.write_u8(self.durability_level_frame.as_ref().unwrap().durability_level)?;
            } else {
                write_frame_header(&mut buffer, 1, 3)?;
                buffer.write_u8(self.durability_level_frame.as_ref().unwrap().durability_level)?;
                buffer.write_u16::<BigEndian>(self.durability_timeout_frame.as_ref().unwrap().durability_timeout as u16)?;
            }
        }

        if self.stream_id_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use stream id frame in non-request packets"));
            }

            write_frame_header(&mut buffer, 2, 2)?;
            buffer.write_u16::<BigEndian>(self.stream_id_frame.as_ref().unwrap().stream_id)?;
        }

        if self.open_tracing_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use open tracing frame in non-request packets"));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x13) {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use open tracing frames without enabling the feature"));
            }

            let trace_ctx_len = self.open_tracing_frame.as_ref().unwrap().trace_context.len();
            write_frame_header(&mut buffer, 3, trace_ctx_len as u8)?;
            buffer.write(&self.open_tracing_frame.as_ref().unwrap().trace_context)?;
        }

        if self.server_duration_frame.is_some() {
            if self.magic != CMD_MAGIC_RES {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use server duration frame in non-response packets"));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0xf) {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use server duration frames without enabling the feature"));
            }

            write_frame_header(&mut buffer, 0, 2)?;
            buffer.write_u16::<BigEndian>(self.server_duration_frame.as_ref().unwrap().server_duration as u16)?;
        }

        if self.user_impersonation_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use user impersonation frame in non-request packets"));
            }

            let user_ctx_len = self.user_impersonation_frame.as_ref().unwrap().user.len();
            write_frame_header(&mut buffer, 4, user_ctx_len as u8)?;
            buffer.write(&self.user_impersonation_frame.as_ref().unwrap().user)?;
        }

        if self.preserve_expiry_frame.is_some() {
            if self.magic != CMD_MAGIC_REQ {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use preserve expiry frame in non-request packets"));
            }

            if !FEATURE_MAP.lock().unwrap().contains_key(&0x14) {
                return Err(io::Error::new(io::ErrorKind::Other, "cannot use preserve expiry frames without enabling the feature"));
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

    fn send(&mut self, mut stream: &TcpStream) -> io::Result<&mut Self> {
        self.opaque = *OPAQUE.lock().unwrap();
        let mut opaque = OPAQUE.lock().unwrap();
        *opaque += 1;

        let buffer = self.to_buffer()?;
        stream.write_all(&buffer)?;
        Ok(self)
    }

    fn then(&mut self, callback: PacketCallback) -> &mut Self {
        let mut opaque_map = OPAQUE_MAP.lock().unwrap();
        opaque_map.insert(self.opaque, callback);

        self.callback = Option::from(callback);
        self
    }
}

fn listen_for_messages(stream: &TcpStream, callback: ListenerCallback) -> io::Result<()> {
    let mut reader: BufReader<&TcpStream> = BufReader::new(stream);

    loop {
        let packet = Packet::from_buffer(&mut reader)?;

        if packet.status != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "got error response"));
        }

        if OPAQUE_MAP.lock().unwrap().contains_key(&packet.opaque) {
            let mut opaque_map = OPAQUE_MAP.lock().unwrap();
            let callback = opaque_map.remove(&packet.opaque).unwrap();

            callback(&packet);
        }

        if packet.command == 0x57 || packet.command == 0x58 || packet.command == 0x59 {
            callback(&packet);
        }
    }
}

fn send_hello(stream: &TcpStream) -> io::Result<()> {
    let futures: Vec<u16> = vec![2, 6, 8, 30, 29, 12, 7, 11, 10, 19, 18, 16, 23, 25, 20, 28, 17];
    let mut futures_value = vec![0u8; 0];
    for future in futures.iter() {
        futures_value.write_u16::<BigEndian>(*future)?;
    }

    Packet {
        magic: 128,
        command: 31,
        key: format!("{{\"a\":\"dcp-rs/v0.0.1\",\"i\":\"{}/{}\"}}", format_cb_uid(random_cb_uid()), format_cb_uid(random_cb_uid())).as_bytes().to_vec(),
        value: futures_value,
        ..Default::default()
    }.send(stream)?.then(|packet| {
        let mut i = 0;

        while i < packet.value.len() {
            let feature = BigEndian::read_u16(&packet.value[i..]);
            let mut feature_map = FEATURE_MAP.lock().unwrap();
            feature_map.insert(feature, true);
            i += 2;
        }
    });

    Ok(())
}

fn sasl_list(stream: &TcpStream) -> io::Result<()> {
    Packet {
        magic: 128,
        command: 32,
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn sasl_auth_continue_with_plain(stream: &TcpStream, username: &str, password: &str) -> io::Result<()> {
    let mut user_pass = vec![0u8; 0];
    user_pass.write_u8(0)?;
    user_pass.write(username.as_bytes())?;
    user_pass.write_u8(0)?;
    user_pass.write(password.as_bytes())?;

    Packet {
        magic: 128,
        command: 33,
        key: "PLAIN".as_bytes().to_vec(),
        value: user_pass,
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn select_bucket(stream: &TcpStream, bucket_name: &str) -> io::Result<()> {
    Packet {
        magic: 128,
        command: 137,
        key: bucket_name.as_bytes().to_vec(),
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn open_conn(stream: &TcpStream, group_name: &str) -> io::Result<()> {
    Packet {
        magic: 128,
        command: 80,
        key: group_name.as_bytes().to_vec(),
        extras: vec![0, 0, 0, 0, 0, 0, 0, 1],
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn exec_noop(stream: &TcpStream) -> io::Result<()> {
    let _ = &Packet {
        magic: 128,
        command: 94,
        key: "enable_noop".as_bytes().to_vec(),
        value: "true".as_bytes().to_vec(),
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn enable_expiry_opcode(stream: &TcpStream) -> io::Result<()> {
    let _ = &Packet {
        magic: 128,
        command: 94,
        key: "enable_expiry_opcode".as_bytes().to_vec(),
        value: "true".as_bytes().to_vec(),
        ..Default::default()
    }.send(stream)?;

    Ok(())
}

fn open_stream(stream: &TcpStream) -> io::Result<()> {
    for i in 0..1024 {
        let _ = &Packet {
            magic: 128,
            command: 83,
            v_bucket: i,
            extras: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         255, 255, 255, 255, 255, 255, 255, 255,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            value: "{\"uid\":\"0\",\"collections\":[\"0\"]}".as_bytes().to_vec(), // todo: fill with real data
            ..Default::default()
        }.send(stream)?;
    }

    Ok(())
}

fn get_collection_id(stream: &TcpStream, scope_name: &str, collection_name: &str) -> io::Result<u32> {
    Packet {
        magic: 128,
        command: 187,
        value: format!("{}.{}", scope_name, collection_name).as_bytes().to_vec(),
        ..Default::default()
    }.send(stream)?.then(|packet| {
        let collection_id = BigEndian::read_u32(&packet.extras[8..]);
        println!("collection id: {}", collection_id)
    });

    Ok(0)
}

fn write_msg(mut stream: &TcpStream) -> io::Result<()> {
    send_hello(stream)?;
    sasl_list(stream)?;
    sasl_auth_continue_with_plain(stream, "user", "123456")?;
    select_bucket(stream, "dcp-test")?;
    get_collection_id(stream, "_default", "_default")?;
    open_conn(stream, "example_group")?;
    exec_noop(stream)?;
    enable_expiry_opcode(stream)?;
    open_stream(stream)?;

    stream.flush()?;

    Ok(())
}

// todo: logger
fn main() -> io::Result<()> {
    let listener: ListenerCallback = |packet| {
        println!("{}", packet);
    };

    match TcpStream::connect("localhost:11210") {
        Ok(stream) => {
            let stream = Arc::new(stream);
            let reader = Arc::clone(&stream);

            thread::spawn(move || {
                match write_msg(&stream) {
                    Ok(..) => println!("stream started"),
                    Err(e) => println!("stream cannot started: {}", e),
                }
            });

            match listen_for_messages(&reader, listener) {
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