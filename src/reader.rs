use std::cmp;
use std::io::{self, Read};

use errors::Result;
use frame::Frame;

pub struct Reader<R> {
    reader: R,
    frame: Frame,
    block: Vec<u8>,
    finished: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(mut reader: R,
               verify_header_checksum: bool,
               header_checksum_include_magic: bool)
               -> Result<Self> {
        let frame = Frame::read_header(&mut reader,
                                       verify_header_checksum,
                                       header_checksum_include_magic)?;
        let block = Vec::with_capacity(frame.block_max_size().unwrap_or(4096));
        Ok(Reader {
               reader: reader,
               frame: frame,
               block: block,
               finished: false,
           })
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished {
            Ok(0)
        } else {
            let remaining = if self.block.is_empty() {
                self.frame
                    .read_block(&mut self.reader, &mut self.block)?
            } else {
                self.block.len()
            };

            if remaining == 0 {
                self.finished = true;

                Ok(0)
            } else {
                let read = cmp::min(self.block.len(), buf.len());

                buf[..read].copy_from_slice(&self.block[..read]);

                self.block = self.block.split_off(read);

                Ok(read)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::*;
    use super::super::Reader;

    #[test]
    fn test_read_frame() {
        let flags = FLAG_VERSION_DEFAULT | FLAG_INDEPENDENT | FLAG_BLOCK_CHECKSUM;
        let bd = BLOCKSIZE_256KB;
        let buf = [0x04, 0x22, 0x4D, 0x18,    // magic
                   flags.bits(),
                   bd.bits(),
                   132,                       // header checksum
                   0, 0, 0, 0                 // end mark
                   ];

        let mut r = Reader::new(&buf[..], false, false).unwrap();

        assert_eq!(r.frame.version(), 1);
        assert!(r.frame.independent());
        assert!(r.frame.block_checksum());
        assert!(!r.frame.content_size());
        assert!(!r.frame.content_checksum());
        assert_eq!(r.frame.block_max_size(), Some(256 * 1024));
        assert_eq!(r.frame.header_checksum(false), 132);

        let mut data = vec![];

        assert_eq!(r.read_to_end(&mut data).unwrap(), 0);
    }

    #[test]
    fn test_read_block() {
        let flags = FLAG_VERSION_DEFAULT | FLAG_INDEPENDENT | FLAG_BLOCK_CHECKSUM;
        let bd = BLOCKSIZE_256KB;
        let buf = [0x04, 0x22, 0x4D, 0x18,      // magic
                   flags.bits(),
                   bd.bits(),
                   132,                         // header checksum
                   5, 0, 0, 0,                  // block size
                   64, 116, 101, 115, 116,      // compressed
                   137, 205, 203, 160,          // block checksum
                   0, 0, 0, 0                   // end mark
                   ];

        let mut r = Reader::new(&buf[..], true, false).unwrap();

        let mut data = Vec::new();

        assert_eq!(r.read_to_end(&mut data).unwrap(), 4);
        assert_eq!(String::from_utf8(data).unwrap(), "test");
    }
}