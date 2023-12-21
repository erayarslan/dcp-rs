use crate::dcp_io::packet::Packet;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

pub type CmdMagic = u8;
pub type CmdCode = u8;
pub type StatusCode = u16;
pub type PacketCallback = fn(&Packet);
pub type ListenerCallback = fn(&Packet);

pub static CMD_MAGIC_REQ: CmdMagic = 0x80;
pub static CMD_MAGIC_RES: CmdMagic = 0x81;
pub static CMD_MAGIC_SERVER_REQ: CmdMagic = 0x82;
pub static CMD_MAGIC_REQ_EXT: CmdMagic = 0x08;
pub static CMD_MAGIC_RES_EXT: CmdMagic = 0x18;
static COLLECTION_ID_SUPPORTED_OPS: [i32; 34] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0e, 0x0f, 0x1c, 0x1d, 0x83, 0x94, 0x95, 0xa0, 0xa2,
    0xa8, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0x57,
    0x59, 0x58,
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
    pub static ref COLLECTION_ID_SUPPORTED_TABLE: Box<[u8]> = make_cid_supported_table();
    pub static ref FEATURE_MAP: Mutex<HashMap<u16, bool>> = Mutex::new(HashMap::new());
    pub static ref OPAQUE: Mutex<u32> = Mutex::new(0);
}

pub fn is_command_collection_enabled(cmd: u8) -> bool {
    let cmd_idx = cmd as i32;
    if cmd_idx < 0 || cmd >= COLLECTION_ID_SUPPORTED_TABLE.len() as u8 {
        return false;
    }

    return COLLECTION_ID_SUPPORTED_TABLE[cmd as usize] == 1;
}
