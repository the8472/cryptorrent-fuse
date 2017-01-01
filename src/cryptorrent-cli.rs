#[macro_use]
extern crate rand;
extern crate rustc_serialize;
extern crate clap;
extern crate rpassword;
extern crate cryptorrent;
extern crate bdecode;
#[macro_use] extern crate log;
extern crate log4rs;

use cryptorrent::*;
use std::path::*;
use std::io::Write;
use std::fs::OpenOptions;
use rand::random;
use rustc_serialize::hex::*;
use clap::{Arg, App, SubCommand};
use rpassword::{prompt_password_stdout, prompt_password_stderr};
use std::error::Error;
use std::io::Read;
use std::fs::File;
use bdecode::{DictIter, Kind, Node, decode};
use log::LogLevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;


#[derive(Debug)]
enum CliError {
    InvalidArg(String)
}

use CliError::*;


impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(),std::fmt::Error> {
        write!(f, "{}", self.description())
    }
}

impl Error for CliError {
    fn description(&self) -> &str {
        match *self {
            InvalidArg(ref msg) => msg
        }
    }
}

fn cli() -> Result<(), Box<std::error::Error>> {
    let app = App::new("cryptorrent")
        .arg(Arg::with_name("verbosity").multiple(true).short("v"))
        .subcommand(SubCommand::with_name("decrypt").about("torrent + ciphertext + key -> plaintext")
            .arg(Arg::with_name("torrent").index(1).required(true).help("the torrent file"))
            .arg(Arg::with_name("data").index(2).required(true).help("the encrypted data"))
            .arg(Arg::with_name("outdir").index(3).required(true).help("directory into which the data will be written"))
        ).subcommand(SubCommand::with_name("create").about("plaintext -> torrent + ciphertext + keys")
            .arg(Arg::with_name("source").index(1).required(true).help("source file or directory"))
            .arg(Arg::with_name("outdir").index(2).required(true).help("output dir for torrent and ciphertext"))
            .arg(Arg::with_name("skip").long("nodata").help("only generate the torrent, not the encrypted data"))
            .arg(Arg::with_name("name").short("n").long("name").takes_value(true).help("public name;  embedded in torrent; also used as output file name\n a random name will be used if none is specified"))
            .arg(Arg::with_name("comment").long("pub-comment").takes_value(true).help("public comment"))
            .arg(Arg::with_name("hcomment").long("sec-comment").takes_value(true).help("hidden comment"))
        ).subcommand(SubCommand::with_name("shadow").about("torrent + key -> shadow dictionary")
            .arg(Arg::with_name("torrent").index(1).required(true).help("the torrent file"))
        );

    let args = app.get_matches();

    let stdout = ConsoleAppender::builder().build();

    let loglevel = match args.occurrences_of("verbosity") {
        2 => LogLevelFilter::Trace,
        1 => LogLevelFilter::Debug,
        _ => LogLevelFilter::Info
    };

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(loglevel))
        .unwrap();

    let handle = log4rs::init_config(config).unwrap();



    match args.subcommand() {
        ("decrypt", Some(sub_args)) => {
            let torrent_path = sub_args.value_of("torrent").unwrap();
            let bin_file = sub_args.value_of("data").unwrap();
            let dest_dir = sub_args.value_of("outdir").unwrap();
            let dest_path = Path::new(dest_dir);

            let hexkey = prompt_password_stdout("root or payload key (in hex): ")?;

            let root_key = hexkey.from_hex()?;

            decrypt(&torrent_path, &root_key, dest_path, bin_file)?
        },
        ("create", Some(sub_args)) => {
            let arg1 = sub_args.value_of("source").unwrap();
            let arg2 = sub_args.value_of("outdir").unwrap();
            let skip = sub_args.is_present("skip");
            let name = sub_args.value_of("name");
            let source_path = Path::new(&arg1);
            let dest_dir = Path::new(&arg2);

            if !dest_dir.is_dir() {
                return Err(Box::new(CliError::InvalidArg(format!("{} is not a directory", arg2))));
            }

            let torrent_name = name.map(|n| n.to_owned()).unwrap_or(format!("unnamed{}.cryptor", random::<u64>()));
            let cipher_path = dest_dir.join(&torrent_name);

            let ciphertext_path = if !skip {
                Some(cipher_path.as_path())
            } else {
                None
            };

            // TODO: check how good the random source is
            let root_key = random::<[u8 ; 32]>();
            let keys = Keys::new(&root_key);

            let torrent = create(source_path, &keys, &torrent_name, ciphertext_path);

            debug!("salt: {}", keys.salt.to_hex());
            debug!("payload nonce: {}", keys.payload_nonce.to_hex());
            debug!("shadow nonce: {}", keys.shadow_nonce.to_hex());

            println!("root     key: {}", root_key.to_hex());
            println!("torrent  key: {}", keys.payload.to_hex());
            println!("metainfo key: {}", keys.shadow.to_hex());

            let torrent_path = dest_dir.join(torrent_name + ".torrent");
            let mut out = OpenOptions::new().write(true).create_new(true).open(&torrent_path)?;

            out.write_all(&torrent)?;

            if name.is_none() {
                println!("written to {}", torrent_path.display());
            }
        },
        ("shadow", Some(sub_args)) => {
            let arg1 = sub_args.value_of("torrent").unwrap();
            let hexkey = prompt_password_stderr("Any of the keys (in hex): ")?;

            let key = hexkey.from_hex()?;

            let mut tf = File::open(&arg1)?;

            let mut raw_torrent = vec![];

            tf.read_to_end(&mut raw_torrent)?;

            let decoded = decode(&raw_torrent)?;

            let info = decoded.dict_get(b"info").unwrap();

            match decrypt_shadow(&info, Some(key.as_slice()).into_iter()) {
                Some((keys, shadow)) => {
                    std::io::stdout().write_all(&shadow)?;
                    std::io::stdout().flush();
                },
                None => {
                    return Err(Box::new(CliError::InvalidArg(format!("could not decrypt torrent"))));
                }
            }
        },
        _ => {println!("command not found. use --help for more information");}
    }

    Ok(())
}

fn main() {
    if let Err(e) = cli() {
        writeln!(&mut std::io::stderr(), "error: {}", e.description()).unwrap();
        std::process::exit(1);
    }

}