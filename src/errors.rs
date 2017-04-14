error_chain!{
    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
    }
    errors {
        InvalidFormat(reason: &'static str) {
            description("invalid LZ4 frame format")
            display("invalid LZ4 frame format, {}", reason)
        }
    }
}
