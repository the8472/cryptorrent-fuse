extern crate fuse;

use fuse::*;
use std::io::prelude;
use std::path::*;

mod filesystem;

fn main() {
    let mount_arg = std::env::args().nth(1).unwrap();

    let mount_path = Path::new(&mount_arg);

    println!("{}", mount_path.display());
    let fs = filesystem::CryptorrentFs {};
    mount(fs, &mount_path, &[])
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert!(false);
    }
}
