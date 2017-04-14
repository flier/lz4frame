use std::io::{self, Write};

use errors::Result;
use frame::{Frame, BlockDescriptor, FLAG_NONE, FLAG_BLOCK_CHECKSUM, FLAG_CONTENT_CHECKSUM};

pub struct Writer<'a, W: 'a + Write> {
    writer: &'a mut W,
    frame: Frame,
    buf: Vec<u8>,
    closed: bool,
}

impl<'a, W: Write> Writer<'a, W> {
    pub fn new(writer: &'a mut W,
               header_checksum_include_magic: bool,
               block_max_size: BlockDescriptor,
               block_checksum: bool,
               content_checksum: bool,
               content_size: Option<u64>)
               -> Result<Writer<'a, W>> {
        let mut flags = FLAG_NONE;

        if block_checksum {
            flags |= FLAG_BLOCK_CHECKSUM
        }
        if content_checksum {
            flags |= FLAG_CONTENT_CHECKSUM
        }

        let frame = Frame::new(flags, block_max_size, content_size);

        frame
            .write_header(writer, header_checksum_include_magic)?;

        let buf = frame
            .block_max_size()
            .map_or_else(|| Vec::new(), |size| Vec::with_capacity(size));

        Ok(Writer {
               writer: writer,
               frame: frame,
               buf: buf,
               closed: false,
           })
    }

    fn write_block(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            debug!("compress {} bytes block: {:?}",
                   self.buf.len(),
                   &self.buf[..16]);

            self.frame.write_block(&mut self.writer, &self.buf[..])?;

            self.buf.clear();
        }

        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.write_block()?;
        self.frame.write_end_mark(&mut self.writer)?;
        self.writer.flush()?;
        self.closed = true;

        Ok(())
    }
}

impl<'a, W: Write> Drop for Writer<'a, W> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.close();
        }
    }
}

impl<'a, W: Write> Write for Writer<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = match self.frame.block_max_size() {
            Some(max_size) if self.buf.len() + buf.len() > max_size => {
                let write_size = max_size - self.buf.len();
                self.buf.extend_from_slice(&buf[..write_size]);
                Some(&buf[write_size..])
            }
            _ => {
                self.buf.extend_from_slice(buf);
                None
            }
        };

        self.write_block()?;

        if let Some(remaining) = remaining {
            self.write(remaining)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_block()?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::*;
    use super::super::Writer;


    #[test]
    fn test_write_frame() {
        let mut buf = vec![];
        {
            let mut w = Writer::new(&mut buf, false, BLOCKSIZE_64KB, false, false, None).unwrap();

            w.close().unwrap();
        }

        let flags = FLAG_VERSION_DEFAULT | FLAG_INDEPENDENT;
        let bd = BLOCKSIZE_64KB;

        assert_eq!(buf.as_slice(),
                   &[0x04, 0x22, 0x4D, 0x18,    // magic
                     flags.bits(),
                     bd.bits(),
                     130,                       // header checksum
                     0, 0, 0, 0                 // end mark
                     ]);
    }

    #[test]
    fn test_write_block() {
        let mut buf = vec![];
        {
            let mut w = Writer::new(&mut buf, false, BLOCKSIZE_64KB, true, false, None).unwrap();

            assert_eq!(w.write(b"test").unwrap(), 4);

            w.close().unwrap();
        }

        let flags = FLAG_VERSION_DEFAULT | FLAG_INDEPENDENT | FLAG_BLOCK_CHECKSUM;
        let bd = BLOCKSIZE_64KB;

        assert_eq!(buf.as_slice(),
                   &[0x04, 0x22, 0x4D, 0x18,        // magic
                     flags.bits(),
                     bd.bits(),
                     173,                           // header checksum
                     5, 0, 0, 0,                    // block size
                     64, 116, 101, 115, 116,        // compressed
                     137, 205, 203, 160,            // block checksum
                     0, 0, 0, 0                     // end mark
                     ]);
    }
}