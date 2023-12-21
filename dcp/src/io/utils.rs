use byteorder::WriteBytesExt;
use std::io;

pub fn append_uleb128_32(b: &mut Vec<u8>, mut v: u32) {
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

pub fn decode_uleb128_32(b: &[u8]) -> io::Result<(u32, usize)> {
    if b.len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "no data provided"));
    }

    let mut u: u64 = 0;
    let mut n: usize = 0;
    let i: usize = 0;

    loop {
        if i >= b.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "encoded number is longer than provided data",
            ));
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "encoded data is longer than 32 bits",
        ));
    }

    Ok((u as u32, n))
}

pub fn calc_header_size(frame_len: usize) -> usize {
    if frame_len < 15 {
        return 1 + frame_len;
    }

    return 2 + frame_len;
}

pub fn random_cb_uid() -> Vec<u8> {
    let mut out = vec![0u8; 8];
    for i in 0..8 {
        out[i] = rand::random::<u8>();
    }

    out
}

pub fn format_cb_uid(data: Vec<u8>) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
    )
}

pub fn write_frame_header(buffer: &mut Vec<u8>, frame_type: u8, frame_len: u8) -> io::Result<()> {
    if frame_len < 15 {
        buffer.write_u8((frame_type << 4) | frame_len)?;
        return Ok(());
    }

    buffer.write_u8((frame_type << 4) | 15)?;
    buffer.write_u8(frame_len - 15)?;
    Ok(())
}
