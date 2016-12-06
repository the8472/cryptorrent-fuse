#[macro_use]
extern crate bip_bencode;
extern crate walkdir;
extern crate rand;
extern crate itertools;
extern crate crypto;
extern crate rustc_serialize;
extern crate clap;
extern crate rpassword;

use bip_bencode::*;
use bip_bencode::Bencode::*;
use std::path::*;
use std::io::{Read,Write};
use std::fs::{File,OpenOptions};
use walkdir::WalkDir;
use rand::random;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;
use std::thread;
use std::sync::mpsc::sync_channel;
use rustc_serialize::hex::*;
use clap::{Arg, App, SubCommand};
use rpassword::read_password;


struct Keys {
    salt: [u8 ; 32],
    root: Vec<u8>,
    payload: [u8 ; 32],
    shadow: [u8 ; 32],
    shadow_nonce : [u8 ; 32],
    payload_nonce : [u8 ; 32]
}

impl Keys {
    fn new(root : Vec<u8>) -> Keys {
        Keys::rebuild(root, random::<[u8 ; 32]>())
    }

    fn rebuild(root: Vec<u8>, salt: [u8 ; 32]) -> Keys {

        let mut derive = Sha256::new();


        let mut derivation_salt = [0 ; 32+7];
        derivation_salt[0..32].copy_from_slice(salt.as_ref());
        derivation_salt[32..].copy_from_slice(&b"payload"[..]);

        let mut payload_nonce = [0 ; 32];

        derive.reset();
        derive.input(&salt); derive.input(&b"payload"[..]);
        derive.result(&mut payload_nonce);

        let mut payload_key = [0 ; 32];

        pbkdf2(&mut Hmac::new(Sha256::new(), &root), &derivation_salt, 4096, &mut payload_key);

        let mut shadow_key = [0 ; 32];
        derive.reset();
        derive.input(&payload_key); derive.input(&b"shadow"[..]);
        derive.result(&mut shadow_key);

        let mut shadow_nonce = [0 ; 32];
        derive.reset();
        derive.input(&salt); derive.input(b"shadow".as_ref());
        derive.result(&mut shadow_nonce);



        Keys{salt: salt, root: root, payload: payload_key, shadow_nonce: shadow_nonce, shadow: shadow_key, payload_nonce: payload_nonce}
    }

    fn shadow_cipher(&self) -> ChaCha20 {
        ChaCha20::new(&self.shadow, &self.shadow_nonce[0..12])
    }

    fn payload_cipher(&self) -> ChaCha20 {
        ChaCha20::new(&self.payload, &self.payload_nonce[0..12])
    }
}


fn create(target : &Path, keys: &Keys, pub_name: &str, output : Option<&Path>) -> Vec<u8> {

    let name : Vec<_> = target.file_name().unwrap().to_string_lossy().bytes().collect();
    let public_name : Vec<_> = pub_name.bytes().collect();
    let mut len : u64 = 0;

    let piece_size = 17*16*1024;


    let mut ciphertext_writer = if let Some(ref cipher_path) = output {
        Some(OpenOptions::new().write(true).create_new(true).open(cipher_path).expect("could not open destination file or already exists"))
    } else {
        None
    };


    let mut files : Vec<(Vec<Vec<u8>>, i64)> = vec![];

    let (tx_plaintext,rx_plaintext) = sync_channel::<Option<Vec<u8>>>(15);
    let (tx_ciphertext,rx_ciphertext) = sync_channel::<Option<Vec<u8>>>(15);



    let mut piece_cipher = keys.payload_cipher();

    let crypter = thread::spawn(move|| {
        while let Ok(Some(chunk)) = rx_plaintext.recv() {
            let mut ciphertext = vec![0 ; chunk.len()];

            piece_cipher.process(&chunk, ciphertext.as_mut());

            if let Some(ref mut w) = ciphertext_writer {
                w.write_all(&ciphertext).unwrap();
            }

            tx_ciphertext.send(Some(ciphertext)).unwrap();
        }

        tx_ciphertext.send(None).unwrap();
    });

    let hasher = thread::spawn(move|| {
        let mut ph = vec![];
        let mut piece_hasher = Sha1::new();

        let mut piece_hash = [0 as u8 ; 20];
        while let Ok(Some(chunk)) = rx_ciphertext.recv() {
            piece_hasher.reset();
            piece_hasher.input(chunk.as_ref());
            piece_hasher.result(&mut piece_hash);
            ph.extend_from_slice(&piece_hash);
        }

        ph
    });


    {
        let mut file_iter = WalkDir::new(target).into_iter().filter_map(|r| match r {
            Ok(p) => Some(p),
            Err(msg) => { writeln!(&mut std::io::stderr(), "warning: skipping file {}", msg).unwrap();None}
        }).filter(|dent| dent.file_type().is_file()).map(|dir_entry| {
            let path = dir_entry.path().to_owned();

            let file = File::open(&path).unwrap();

            let path_chunks = path.strip_prefix(target).into_iter().map(|ostr| ostr.to_string_lossy().bytes().collect::<Vec<u8>>()).collect();
            files.push((path_chunks, file.metadata().unwrap().len() as i64));

            file
        }).peekable();

        let mut read_buf = vec![0 ; piece_size];
        let mut bytes_read = 0;

        'files: while let Some(mut file) = file_iter.next() {
            let have_more = file_iter.peek().is_some();

            loop {
                let bytes = file.read(&mut read_buf[bytes_read..]).unwrap();
                if bytes == 0 && have_more && bytes_read < piece_size {
                    continue 'files;
                }

                bytes_read += bytes;
                len += bytes as u64;

                if bytes_read == piece_size || bytes == 0 {
                    // TODO: padding
                    let vec : Vec<_> = (&read_buf[..bytes_read]).to_owned();
                    tx_plaintext.send(Some(vec)).unwrap();
                    bytes_read = 0;
                }

                if bytes == 0 {
                    break;
                }
            }

        }

    }

    tx_plaintext.send(None).unwrap();

    let piece_hashes = hasher.join().unwrap();

    let shadow = ben_map!{
        "files" => List((&files).iter().map(|&(ref paths, len)| ben_map!{
            "path" => List(paths.iter().map(|p| ben_bytes!(p)).collect()),
            "length" => Int(len as i64)
        }).collect()),
        "name" => Bytes(&name)
    };



    let encoded_shadow = shadow.encode();
    let mut encrypted_shadow = vec![0 ; encoded_shadow.len()];
    let mut shadow_cipher = keys.shadow_cipher();
    shadow_cipher.process(&encoded_shadow, &mut encrypted_shadow);

    let mac_placeholder = [0 ; 32];

    let info : Bencode = ben_map!{
        "bepXX" => ben_map!{
            "mac" => Bytes(&mac_placeholder),
            "salt" => Bytes(&keys.salt),
            "shadow" => Bytes(&encrypted_shadow),
            "v" => ben_int!(1)
        },
        "piece length" => Int(piece_size as i64),
        "pieces" => Bytes(&piece_hashes),
        "name" => Bytes(&public_name),
        "length" => Int(len as i64)
    };

    let incomplete_dict = info.encode();

    let mut hmac = Hmac::new(Sha256::new(), &keys.shadow);
    hmac.input(&incomplete_dict);
    let mac_result = hmac.result();
    let raw_mac = mac_result.code();

    assert!(raw_mac.len() == 32);

    let mut root = ben_map!{"info" => info}.encode();

    let prefix = b"3:mac32:";
    let mut needle = [0 ; 8 + 32];

    needle[..8].copy_from_slice(prefix.as_ref());

    let offset = root.windows(needle.len()).position(|chunk| {
        chunk == needle.as_ref()
    }).unwrap() + prefix.len();


    root[offset..offset+32].copy_from_slice(raw_mac.as_ref());

    return root;
}

fn main() {
    let app = App::new("cryptorrent")
        .subcommand(SubCommand::with_name("decrypt")
            .arg(Arg::with_name("torrent").index(1).required(true).help("the torrent file"))
            .arg(Arg::with_name("data").index(2).required(true).help("the encrypted data"))
            .arg(Arg::with_name("outdir").index(3).required(true).help("directory into which the data will be written"))
        ).subcommand(SubCommand::with_name("create")
            .arg(Arg::with_name("source").index(1).required(true).help("source file or directory"))
            .arg(Arg::with_name("outdir").index(2).required(true).help("output dir for torrent and ciphertext"))
            .arg(Arg::with_name("skip").long("nodata").help("only generate the torrent, not the encrypted data"))
            .arg(Arg::with_name("name").short("n").long("name").takes_value(true).help("public name;  embedded in torrent; also used as output file name\n a random name will be used if none is specified"))
            .arg(Arg::with_name("comment").long("pub-comment").takes_value(true).help("public comment"))
            .arg(Arg::with_name("hcomment").long("sec-comment").takes_value(true).help("hidden comment"))
        );

    let args = app.get_matches();

    match args.subcommand() {
        ("decrypt", Some(sub_args)) => {
            let torrent_path = sub_args.value_of("torrent").unwrap();
            let bin_file = sub_args.value_of("data").unwrap();
            let dest_dir = sub_args.value_of("outdir").unwrap();
            let dest_path = Path::new(dest_dir);

            let hexkey = rpassword::prompt_password_stdout("Root Key: ").unwrap();

            let root_key = hexkey.from_hex().unwrap();

            let mut tf = File::open(torrent_path).unwrap();

            let mut raw_torrent = vec![];

            tf.read_to_end(&mut raw_torrent).unwrap();

            let torrent = Bencode::decode(&raw_torrent).unwrap();

            let info = torrent.dict().unwrap().lookup("info").unwrap().dict().unwrap();
            let crypto_meta = info.lookup("bepXX").unwrap().dict().unwrap();
            let shadow = crypto_meta.lookup("shadow").unwrap().bytes().unwrap();
            let raw_salt = crypto_meta.lookup("salt").unwrap().bytes().unwrap();

            assert_eq!(raw_salt.len(), 32);

            let mut salt = [0 ; 32];
            salt.copy_from_slice(raw_salt.as_ref());


            let keys = Keys::rebuild(root_key, salt);

            let mut shadow_cipher = keys.shadow_cipher();

            let mut decrypted_shadow = vec![0 ; shadow.len()];


            shadow_cipher.process(shadow, decrypted_shadow.as_mut());

            //println!("{}", String::from_utf8_lossy(&decrypted_shadow));

            let shadow_root = Bencode::decode(&decrypted_shadow).unwrap();
            let shadow_dict = shadow_root.dict().unwrap();

            let inner_name = shadow_dict.lookup("name").unwrap().str().unwrap();
            let files = shadow_dict.lookup("files").unwrap().list().unwrap();

            let mut input = File::open(bin_file).unwrap();

            let mut read_buffer = vec![0 ; 32 * 1024];
            let mut write_buffer = vec![0 ; 32 * 1024];

            let mut payload_cipher = keys.payload_cipher();

            for file in files {
                let file_dict = file.dict().unwrap();
                let len = file_dict.lookup("length").unwrap().int().unwrap() as usize;
                let path_list = file_dict.lookup("path").unwrap().list().unwrap();

                let mut path = PathBuf::new();
                path.push(inner_name);
                for path_element in path_list {
                    let pe = path_element.str().unwrap();
                    if pe.len() > 0 {
                        path.push(pe);
                    }

                }

                let full_path = dest_path.join(path);

                std::fs::create_dir_all(full_path.parent().unwrap());

                println!("{}", full_path.as_path().to_string_lossy());

                let mut out = OpenOptions::new().write(true).create_new(true).open(full_path).unwrap();

                let mut offset : usize = 0;

                while offset < len {
                    let to_read = std::cmp::min(read_buffer.len(), len - offset);
                    let read = input.read(&mut read_buffer[..to_read]).unwrap();

                    offset += read;

                    payload_cipher.process(&read_buffer[..read], &mut write_buffer[..read]);

                    out.write_all(&write_buffer[..read]).unwrap();
                }
            }







        },
        ("create", Some(sub_args)) => {
            let arg1 = sub_args.value_of("source").unwrap();
            let arg2 = sub_args.value_of("outdir").unwrap();
            let skip = sub_args.is_present("skip");
            let name = sub_args.value_of("name");
            let source_path = Path::new(&arg1);
            let dest_dir = Path::new(&arg2);

            if !dest_dir.is_dir() {
                writeln!(&mut std::io::stderr(), "{} is not a directory", arg2);
                std::process::exit(1);
            }

            let torrent_name = name.map(|n| n.to_owned()).unwrap_or(format!("unnamed{}.cryptor", random::<u64>()));
            let cipher_path = dest_dir.join(&torrent_name);

            let ciphertext_path = if !skip {
                Some(cipher_path.as_path())
            } else {
                None
            };

            let root_key = random::<[u8 ; 32]>();
            let keys = Keys::new(root_key.to_vec());

            let torrent = create(source_path, &keys, &torrent_name, ciphertext_path);

            println!("root     key: {}", root_key.to_hex());
            println!("torrent  key: {}", keys.payload.to_hex());
            println!("metainfo key: {}", keys.shadow.to_hex());

            let torrent_path = dest_dir.join(torrent_name + ".torrent");
            let mut out = OpenOptions::new().write(true).create_new(true).open(&torrent_path).expect("could not open destination file or already exists");

            out.write_all(&torrent).unwrap();

            if name.is_none() {
                println!("written to {}", torrent_path.display());
            }
        },
        _ => {println!("command not found. use --help for more information");}
    }


}