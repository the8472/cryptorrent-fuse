extern crate cryptorrent;
extern crate fuse;
#[macro_use] extern crate log;
extern crate log4rs;

use cryptorrent::*;
use cryptorrent::filesystem::*;
use fuse::*;
use std::io::prelude;
use std::path::*;
use log::LogLevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;



fn main() {

    let stdout = ConsoleAppender::builder().build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LogLevelFilter::Trace))
        .unwrap();

    let handle = log4rs::init_config(config).unwrap();

    let mount_arg = std::env::args().nth(1).unwrap();
    let src_dir = std::env::args().nth(2).unwrap();
    let keyfile = std::env::args().nth(3).unwrap();

    let mount_path = Path::new(&mount_arg);

    println!("{}", mount_path.display());

    let mut fs = filesystem::CryptorrentFs::new();
    fs.add_keyfile(&keyfile);
    fs.add_source_dir(&src_dir);
    mount(fs, &mount_path, &[])
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert!(false);
    }
}
