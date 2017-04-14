#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate lz4_compress;
extern crate xxhash2;

mod errors;
mod frame;
mod reader;
mod writer;

pub use frame::Frame;
pub use reader::Reader;
pub use writer::Writer;