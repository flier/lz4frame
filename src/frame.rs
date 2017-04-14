use std::mem;
use std::ops::{Range, Deref};
use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use lz4_compress;

use xxhash2;

use errors::{ErrorKind, Result};

bitflags! {
    pub flags FrameFlags: u8 {
        const FLAG_NONE             = 0b00000000,
        const FLAG_CONTENT_CHECKSUM = 0b00000100,
        const FLAG_CONTENT_SIZE     = 0b00001000,
        const FLAG_BLOCK_CHECKSUM   = 0b00010000,
        const FLAG_INDEPENDENT      = 0b00100000,
        const FLAG_VERSION_DEFAULT  = 0b01000000,
        const FLAG_VERSION_MASK     = 0b11000000,
    }
}

impl FrameFlags {
    /// Version Number, must be set to “01”.
    pub fn version(&self) -> u8 {
        (*self & FLAG_VERSION_MASK).bits >> FLAG_VERSION_SHIFT
    }

    /// Blocks are independent.
    pub fn independent(&self) -> bool {
        self.contains(FLAG_INDEPENDENT)
    }

    /// Each data block will be followed by a checksum,
    pub fn block_checksum(&self) -> bool {
        self.contains(FLAG_BLOCK_CHECKSUM)
    }

    /// The uncompressed size of data included within the frame
    pub fn content_size(&self) -> bool {
        self.contains(FLAG_CONTENT_SIZE)
    }

    pub fn content_checksum(&self) -> bool {
        self.contains(FLAG_CONTENT_CHECKSUM)
    }
}

bitflags! {
    pub flags BlockDescriptor: u8 {
        const BLOCKSIZE_NONE        = 0b00000000,
        const BLOCKSIZE_64KB        = 0b01000000,
        const BLOCKSIZE_256KB       = 0b01010000,
        const BLOCKSIZE_1MB         = 0b01100000,
        const BLOCKSIZE_4MB         = 0b01110000,
        const BLOCKSIZE_DEFAULT     = BLOCKSIZE_64KB.bits,
        const BLOCKSIZE_MASK        = BLOCKSIZE_64KB.bits |
                                      BLOCKSIZE_256KB.bits |
                                      BLOCKSIZE_1MB.bits |
                                      BLOCKSIZE_4MB.bits,
    }
}

const LZ4_MAGIC: u32 = 0x184D2204;

const LZ4_FRAME_INCOMPRESSIBLE_MASK: u32 = 0x80000000;

const FLAG_VERSION_SHIFT: u8 = 6;

/// see also: LZ4 Frame Format Description <https://github.com/lz4/lz4/wiki/lz4_Frame_format.md>
pub struct Frame {
    flags: FrameFlags,
    bd: BlockDescriptor,
    content_size: Option<u64>,
    content_hash: Option<xxhash2::State32>,
}

impl Deref for Frame {
    type Target = FrameFlags;

    fn deref(&self) -> &Self::Target {
        &self.flags
    }
}

impl Frame {
    pub fn new(flags: FrameFlags, bd: BlockDescriptor, content_size: Option<u64>) -> Self {
        Frame {
            flags: flags | FLAG_VERSION_DEFAULT | FLAG_INDEPENDENT |
                   content_size.map_or(FLAG_NONE, |_| FLAG_CONTENT_SIZE),
            bd: bd |
                if (bd & BLOCKSIZE_MASK) == BLOCKSIZE_NONE {
                    BLOCKSIZE_DEFAULT
                } else {
                    BLOCKSIZE_NONE
                },
            content_size: content_size,
            content_hash: if flags.content_checksum() {
                Some(xxhash2::State32::new())
            } else {
                None
            },
        }
    }

    pub fn block_max_size(&self) -> Option<usize> {
        match self.bd & BLOCKSIZE_MASK {
            BLOCKSIZE_64KB => Some(64 * 1024),
            BLOCKSIZE_256KB => Some(256 * 1024),
            BLOCKSIZE_1MB => Some(1024 * 1024),
            BLOCKSIZE_4MB => Some(4 * 1024 * 1024),
            _ => None,
        }
    }

    pub fn header_checksum(&self, include_magic: bool) -> u8 {
        let mut header = Vec::with_capacity(14);

        if include_magic {
            header.write_u32::<LittleEndian>(LZ4_MAGIC).unwrap();
        }

        header.write(&[self.flags.bits, self.bd.bits]).unwrap();

        if let Some(size) = self.content_size {
            header.write_u64::<LittleEndian>(size).unwrap();
        }

        ((xxhash2::hash32(&header[..], 0) >> 8) & 0xFF) as u8
    }

    pub fn read_header<R: Read>(reader: &mut R,
                                verify_header_checksum: bool,
                                header_checksum_include_magic: bool)
                                -> Result<Frame> {
        let magic = reader.read_u32::<LittleEndian>()?;

        if magic != LZ4_MAGIC {
            bail!(ErrorKind::InvalidFormat("header magic mismatch"))
        } else {
            let flags = FrameFlags::from_bits_truncate(reader.read_u8()?);
            let bd = BlockDescriptor::from_bits_truncate(reader.read_u8()?);
            let content_size = if flags.content_size() {
                Some(reader.read_u64::<LittleEndian>()?)
            } else {
                None
            };
            let checksum = reader.read_u8()?;

            let frame = Frame::new(flags, bd, content_size);

            if verify_header_checksum &&
               frame.header_checksum(header_checksum_include_magic) != checksum {
                bail!(ErrorKind::InvalidFormat("header checksum mismatch"))
            } else {
                Ok(frame)
            }
        }
    }

    pub fn write_header<W: Write>(&self, writer: &mut W, include_magic: bool) -> Result<usize> {
        writer.write_u32::<LittleEndian>(LZ4_MAGIC)?;
        writer.write_u8(self.flags.bits)?;
        writer.write_u8(self.bd.bits)?;

        let mut wrote = mem::size_of_val(&LZ4_MAGIC) + 2;

        if let Some(size) = self.content_size {
            writer.write_u64::<LittleEndian>(size)?;
            wrote += mem::size_of_val(&size);
        }

        writer.write_u8(self.header_checksum(include_magic))?;
        wrote += 1;

        Ok(wrote)
    }

    pub fn read_block<R: Read>(&self, reader: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
        let (block_size, mut compressed_data) = match reader.read_u32::<LittleEndian>()? {
            0 => (0, None),
            n if n & LZ4_FRAME_INCOMPRESSIBLE_MASK == 0 => (n as usize, Some(vec![0; n as usize])),
            n @ _ => ((n ^ LZ4_FRAME_INCOMPRESSIBLE_MASK) as usize, None),
        };

        debug!("reading {} bytes block", block_size);

        if block_size == 0 {
            if self.flags.content_checksum() {
                reader.read_u32::<LittleEndian>()?; // TODO: verify this content checksum
            }
        } else {
            let read_buf = if let Some(data) = compressed_data.as_mut() {
                &mut data[..]
            } else {
                let off = buf.len();
                buf.resize(off + block_size, 0);
                &mut buf[off..]
            };

            reader.read(read_buf)?;

            if self.flags.block_checksum() &&
               reader.read_u32::<LittleEndian>()? != xxhash2::hash32(read_buf, 0) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "block checksum mismatch"));
            }
        }

        if let Some(data) = compressed_data.as_ref() {
            let mut uncompressed_data =
                lz4_compress::decompress(data)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decompress failed"))?;
            let uncompressed_size = uncompressed_data.len();

            debug!("uncompress {} bytes block: {:?}",
                   uncompressed_size,
                   &uncompressed_data[..16]);

            buf.append(&mut uncompressed_data);

            Ok(uncompressed_size)
        } else {
            Ok(block_size)
        }
    }

    pub fn write_block<W: Write>(&self, writer: &mut W, buf: &[u8]) -> io::Result<usize> {
        debug!("write {} bytes block: {:?}", buf.len(), &buf[..16]);

        let compressed_data = lz4_compress::compress(buf);
        writer
            .write_u32::<LittleEndian>(compressed_data.len() as u32)?;
        let mut wrote = mem::size_of::<u32>();
        wrote += writer.write(&compressed_data[..])?;
        if self.flags.block_checksum() {
            writer
                .write_u32::<LittleEndian>(xxhash2::hash32(&compressed_data[..], 0))?;
            wrote += 2;
        }
        Ok(wrote)
    }

    pub fn write_end_mark<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_u32::<LittleEndian>(0)?;
        if self.flags.content_checksum() {
            let checksum = if let Some(ref hash) = self.content_hash {
                hash.finish()
            } else {
                0
            };

            writer.write_u32::<LittleEndian>(checksum)?;
        }
        Ok(mem::size_of::<u32>())
    }
}