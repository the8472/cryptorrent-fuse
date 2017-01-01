#[macro_use] extern crate bip_bencode;
extern crate bdecode;
extern crate walkdir;
extern crate rand;
extern crate itertools;
extern crate crypto;
extern crate rustc_serialize;
extern crate clap;
extern crate rpassword;
extern crate fuse;
extern crate chacha;
#[macro_use] extern crate log;
#[macro_use] extern crate arrayref;

use bip_bencode::*;
use bip_bencode::Bencode::*;
use bdecode::{DictIter, Kind, Node, decode};
use std::path::*;
use std::io::{Read,Write,Seek,SeekFrom};
use std::fs::{File,OpenOptions};
use std::collections::HashMap;
use std::sync::Arc;
use walkdir::WalkDir;
use rand::random;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2::pbkdf2;
use crypto::scrypt::*;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;
use std::thread;
use std::sync::mpsc::sync_channel;
use rustc_serialize::hex::*;
use clap::{Arg, App, SubCommand};
use rpassword::prompt_password_stdout;
use std::error::Error;
use chacha::*;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub mod filesystem;

#[derive(Debug)]
pub struct Keys {
    pub salt: [u8 ; 32],
    pub payload: [u8 ; 32],
    pub shadow: [u8 ; 32],
    pub shadow_nonce : [u8 ; 32],
    pub payload_nonce : [u8 ; 32]
}

impl Keys {
    pub fn new(root : &[u8]) -> Keys {
        Keys::from_root(root, random::<[u8 ; 32]>())
    }

    fn from_payload(payload_key: [u8 ; 32], salt : [u8 ; 32]) -> Keys {
        let mut derive = Sha256::new();

        let mut payload_nonce = [0 ; 32];

        derive.reset();
        derive.input(&salt); derive.input(&b"payload"[..]);
        derive.result(&mut payload_nonce);


        let mut shadow_key = [0 ; 32];
        derive.reset();
        derive.input(&payload_key); derive.input(&b"shadow"[..]);
        derive.result(&mut shadow_key);

        let mut shadow_nonce = [0 ; 32];
        derive.reset();
        derive.input(&salt); derive.input(b"shadow".as_ref());
        derive.result(&mut shadow_nonce);

        Keys{salt: salt, payload: payload_key, shadow_nonce: shadow_nonce, shadow: shadow_key, payload_nonce: payload_nonce}
    }

    fn from_root(root: &[u8], salt: [u8 ; 32]) -> Keys {


        let mut derivation_salt = [0 ; 32+7];
        derivation_salt[0..32].copy_from_slice(salt.as_ref());
        derivation_salt[32..].copy_from_slice(&b"payload"[..]);

        let mut payload_key = [0 ; 32];

        //pbkdf2(&mut Hmac::new(Sha256::new(), &root), &derivation_salt, 4096, &mut payload_key);
        scrypt(root, &salt, &ScryptParams::new(14, 8, 1), &mut payload_key);

        Keys::from_payload(payload_key, salt)
    }

    fn from_meta(meta_key: [u8 ; 32], salt : [u8 ; 32]) -> Keys {
        let mut derive = Sha256::new();

        let mut dummy = [0 ; 32];

        let mut shadow_nonce = [0 ; 32];
        derive.reset();
        derive.input(&salt); derive.input(b"shadow".as_ref());
        derive.result(&mut shadow_nonce);

        Keys{salt: salt, payload: dummy, shadow_nonce: shadow_nonce, shadow: meta_key, payload_nonce: dummy}

    }

    fn shadow_cipher(&self) -> ChaCha20 {
        ChaCha20::new(&self.shadow, &self.shadow_nonce[0..8])
    }

    fn payload_cipher(&self) -> ChaCha20 {
        ChaCha20::new(&self.payload, &self.payload_nonce[0..8])
    }

    fn seekable_payload_cipher(&self) -> ChaCha {
        ChaCha::new_chacha20(&self.payload, array_ref![&self.payload_nonce,0,8])
    }

    //fn mac<'a, T: Iterator<Item=&'a [u8]>>(&self, chunks : T) -> Vec<u8> {
    fn mac(&self, chunks : &[&[u8]]) -> Vec<u8> {
        let mut hmac = Hmac::new(Sha256::new(), &self.shadow);
        for chunk in chunks {
            hmac.input(chunk);
        }

        hmac.result().code().to_owned()
    }

    fn mac_matches(&self, chunks : &[&[u8]], expected : &[u8]) -> bool {
        let mac = self.mac(chunks);
        expected.eq(mac.as_slice())
    }
}

#[derive(Debug)]
struct TFile {
    path: PathBuf,
    offset: u64,
    length: u64
}

#[derive(Debug)]
struct DecryptedMeta {
    keys: Keys,
    name: PathBuf,
    plaintext_files: Vec<TFile>,
    length: u64,
    piece_size: u64,
    pieces: Vec<u8>,
    ciphertext: Option<PathBuf>
}

pub fn decrypt_shadow<'a, T: Iterator<Item=&'a[u8]>>(info : &Node, key_candidates : T) -> Option<(Keys, Vec<u8>)> {
    let crypto_meta = info.dict_get(b"encrypted").unwrap();
    let mac = crypto_meta.dict_bytes(b"mac").unwrap();
    let raw_salt = crypto_meta.dict_bytes(b"salt").unwrap();
    let shadow = crypto_meta.dict_bytes(b"shadow").unwrap();
    let raw_info = info.raw_bytes();
    let mac_offset : usize = mac.as_ptr() as usize - raw_info.as_ptr() as usize;

    assert_eq!(raw_salt.len(), 32);
    let salt = *array_ref![raw_salt,0,32];

    let mut probed = None;
    let placeholder = [0 ; 32];

    for raw_key in key_candidates {
        let as_root = Keys::from_root(raw_key, salt);

        let chunks = [&raw_info[0..mac_offset], &placeholder[..], &raw_info[mac_offset+32 ..]];

        if as_root.mac_matches(&chunks, &mac) {
            probed = Some(as_root);
            break;
        }

        if raw_key.len() == 32 {
            let mut raw = [0 ; 32];
            raw.copy_from_slice(&raw_key[0..32]);

            let as_payload = Keys::from_payload(raw, salt);

            if as_payload.mac_matches(&chunks, &mac) {
                probed = Some(as_payload);
                break;
            }

            let as_meta = Keys::from_meta(raw, salt);

            if as_meta.mac_matches(&chunks, &mac) {
                probed = Some(as_meta);
                break;
            }

        }

    }


    match probed {
        Some(keys) => {
            let mut shadow_cipher = keys.shadow_cipher();

            let mut decrypted_shadow = vec![0 ; shadow.len()];


            shadow_cipher.process(shadow, decrypted_shadow.as_mut());
            Some((keys, decrypted_shadow))
        },
        None => None
    }

}

impl DecryptedMeta {
    fn new <'a, T: Iterator<Item=&'a[u8]>> (torrent_path: &str, key_candidates : T) -> Result<DecryptedMeta, Box<std::error::Error>> {
        let mut tf = File::open(&torrent_path)?;

        let mut raw_torrent = vec![];

        tf.read_to_end(&mut raw_torrent)?;

        let decoded = decode(&raw_torrent)?;

        let info = decoded.dict_get(b"info").unwrap();

        let (keys, decrypted_shadow) = decrypt_shadow(&info, key_candidates).unwrap();

        let length = info.dict_int(b"length").unwrap();
        let piece_length = info.dict_int(b"piece length").unwrap();
        let pieces = info.dict_bytes(b"pieces").unwrap().to_owned();

        //println!("{}", String::from_utf8_lossy(&decrypted_shadow));

        let shadow_root = Bencode::decode(&decrypted_shadow)?;
        let shadow_dict = shadow_root.dict().unwrap();

        let inner_name = shadow_dict.lookup("name").unwrap().str().unwrap();
        // TODO single file mode
        let files = shadow_dict.lookup("files").unwrap().list().unwrap();

        let mut file_list = vec![];

        let mut offset = 0;

        for file in files {
            let file_dict = file.dict().unwrap();
            let len = file_dict.lookup("length").unwrap().int().unwrap() as u64;
            let foffset = offset;
            offset += len;

            let is_padding = if let Some(attrs) = file_dict.lookup("attr") {
                attrs.bytes().unwrap().contains(&('p' as u8))
            } else {
                false
            };

            if is_padding {
                continue;
            }


            let path_list = file_dict.lookup("path").unwrap().list().unwrap();

            let mut path = PathBuf::new();
            path.push(inner_name);
            for path_element in path_list {
                let pe = path_element.str().unwrap();
                if pe.len() > 0 {
                    path.push(pe);
                }
            }

            file_list.push(TFile{path: path, offset: foffset, length: len});
        }

        Ok(DecryptedMeta {keys: keys, name: Path::new(inner_name).to_owned(), plaintext_files: file_list, length: length, piece_size: piece_length, pieces: pieces, ciphertext: None})
    }
}

pub fn create(target : &Path, keys: &Keys, pub_name: &str, output : Option<&Path>) -> Vec<u8> {

    let name : Vec<_> = target.file_name().unwrap().to_string_lossy().bytes().collect();
    let public_name : Vec<_> = pub_name.bytes().collect();
    let mut ciphertext_length : u64 = 0;

    let piece_size = 17*16*1024;


    // TODO: pass in writer as argument. requires scoped threads
    let mut ciphertext_writer = if let Some(ref cipher_path) = output {
        Some(OpenOptions::new().write(true).create_new(true).open(cipher_path).expect("could not open destination file or already exists"))
    } else {
        None
    };

    struct FileInfo {
        path_segments: Vec<Vec<u8>>,
        offset: u64,
        length: u64,
        sha1: Option<[u8 ; 20]>,
        attrs: Option<Vec<u8>>
    };


    let mut files : Vec<FileInfo> = vec![];

    let (tx_plaintext,rx_plaintext) = sync_channel::<Option<Arc<Vec<u8>>>>(15);
    let (tx_ciphertext,rx_ciphertext) = sync_channel::<Option<Vec<u8>>>(15);
    let (tx_filehash,rx_filehash) = sync_channel::<Option<(usize, Arc<Vec<u8>>)>>(15);



    let mut piece_cipher = keys.payload_cipher();

    let crypter = thread::spawn(move|| {
        while let Ok(Some(chunk)) = rx_plaintext.recv() {
            let mut ciphertext = vec![0 ; chunk.len()];

            piece_cipher.process(&chunk, ciphertext.as_mut_slice());

            if let Some(ref mut w) = ciphertext_writer {
                w.write_all(&ciphertext).unwrap();
            }

            tx_ciphertext.send(Some(ciphertext)).unwrap();
        }

        tx_ciphertext.send(None).unwrap();
    });

    let piecehasher = thread::spawn(move|| {
        let mut ph = vec![];
        let mut piece_hasher = Sha1::new();

        let mut piece_hash = [0 as u8 ; 20];
        let mut remaining = piece_size;
        while let Ok(Some(chunk)) = rx_ciphertext.recv() {

            let mut view = &chunk[..];

            while !view.is_empty() {
                let read = std::cmp::min(view.len(), remaining);
                let ref window = view[..read];

                piece_hasher.input(window);
                remaining -= read;

                if remaining == 0 {
                    remaining = piece_size;

                    piece_hasher.result(&mut piece_hash);
                    piece_hasher.reset();
                    ph.extend_from_slice(&piece_hash);
                }

                view = &view[read..];
            }
        }

        // we did read something, but less than a piece
        if remaining < piece_size {
            piece_hasher.result(&mut piece_hash);
            ph.extend_from_slice(&piece_hash);
        }


        ph
    });

    let filehasher = thread::spawn(move|| {
        let mut map : HashMap<usize, Sha1> = HashMap::new();

        let mut piece_hash = [0 as u8 ; 20];
        while let Ok(Some((idx, chunk))) = rx_filehash.recv() {

            if !map.contains_key(&idx) {
                map.insert(idx, Sha1::new());
            }

            let ref mut file_digest = map.get_mut(&idx).unwrap();
            file_digest.input(chunk.as_slice());
        }

        let res = map.iter_mut().map(|(idx, ref mut digest)| {
            let mut result = [0 ; 20];
            digest.result(&mut result);
            (*idx, result)
        }).collect::<Vec<_>>();

        res
    });


    {
        let mut file_iter = WalkDir::new(target).into_iter().filter_map(|r| match r {
            Ok(p) => Some(p),
            Err(msg) => { writeln!(&mut std::io::stderr(), "warning: skipping file {}", msg).unwrap();None}
        }).filter(|dent| dent.file_type().is_file()).map(|dir_entry| {
            let path = dir_entry.path().to_owned();

            let file = File::open(&path).unwrap();

            (path,file)
        }).peekable();

        let mut read_buf = vec![0 ; 256*1024];
        let mut file_offset = 0;

        'files: while let Some((path, mut file)) = file_iter.next() {

            let path_chunks = path.strip_prefix(target).into_iter().map(|ostr| ostr.to_string_lossy().bytes().collect::<Vec<u8>>()).collect();
            let len = file.metadata().unwrap().len();
            let file_idx = files.len();

            files.push(FileInfo{path_segments: path_chunks, offset: file_offset, length: len, sha1: None, attrs: None});
            file_offset += len;


            let have_more = file_iter.peek().is_some();

            loop {
                let bytes = file.read(read_buf.as_mut_slice()).unwrap();
                if bytes == 0 {
                    continue 'files;
                }

                ciphertext_length += bytes as u64;

                let vec : Vec<_> = (&read_buf[..bytes]).to_owned();
                let shared = std::sync::Arc::new(vec);
                tx_plaintext.send(Some(shared.clone())).unwrap();
                tx_filehash.send(Some((file_idx, shared))).unwrap();
            }

        }

    }

    // padding
    let tail = ciphertext_length % (piece_size as u64);
    if tail != 0 {
        let padding = piece_size as u64 - tail;
        let vec = vec![0 ; padding as usize];
        let shared = std::sync::Arc::new(vec);
        files.push(FileInfo{path_segments: vec![], offset: ciphertext_length, length: padding, sha1: None, attrs: Some(b"p".to_vec())});
        tx_plaintext.send(Some(shared)).unwrap();
        ciphertext_length += padding;
    }

    tx_plaintext.send(None).unwrap();
    tx_filehash.send(None).unwrap();
    crypter.join().unwrap();

    for (idx, hash) in filehasher.join().unwrap() {
        files[idx].sha1 = Some(hash)
    }

    let piece_hashes = piecehasher.join().unwrap();

    let shadow = ben_map!{
        "files" => List((&files).iter().map(|ref fi| {
            let mut map = BTreeMap::new();
            if !fi.path_segments.is_empty() {
                map.insert("path", List(fi.path_segments.iter().map(|p| ben_bytes!(p)).collect()));
            }

            map.insert("length", Int(fi.length as i64));
            if let Some(ref hash) = fi.sha1 {
                map.insert("sha1", ben_bytes![hash]);
            }
            if let Some(ref attrs) = fi.attrs {
                map.insert("attr", ben_bytes![attrs]);
            }

            Dict(map)
        }).collect()),
        "name" => Bytes(&name)
    };



    let encoded_shadow = shadow.encode();

    trace!("shadow: {}", String::from_utf8_lossy(&encoded_shadow));
    let mut encrypted_shadow = vec![0 ; encoded_shadow.len()];
    let mut shadow_cipher = keys.shadow_cipher();
    shadow_cipher.process(&encoded_shadow, &mut encrypted_shadow);

    let mac_placeholder = [0 ; 32];

    let info : Bencode = ben_map!{
        "encrypted" => ben_map!{
            "mac" => Bytes(&mac_placeholder),
            "salt" => Bytes(&keys.salt),
            "shadow" => Bytes(&encrypted_shadow),
            "v" => ben_int!(1)
        },
        "piece length" => Int(piece_size as i64),
        "pieces" => Bytes(&piece_hashes),
        "name" => Bytes(&public_name),
        "length" => Int(ciphertext_length as i64)
    };

    let incomplete_dict = info.encode();

    let raw_mac = keys.mac(&[&incomplete_dict]);

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



pub fn decrypt(torrent_path: &str, root_key : &[u8], dest_path : &Path, bin_file : &str) -> Result<(), Box<std::error::Error>> {

    let k = Some(root_key).into_iter();
    let meta = DecryptedMeta::new(torrent_path, k)?;
    let mut input = File::open(bin_file)?;
    let mut read_buffer = vec![0 ; 32 * 1024];
    let mut payload_cipher = meta.keys.seekable_payload_cipher();

    for file in meta.plaintext_files {
        let piece_space_offset = file.offset;
        payload_cipher.seek_to(piece_space_offset).unwrap();
        input.seek(SeekFrom::Start(piece_space_offset)).unwrap();

        let full_path = dest_path.join(file.path);

        std::fs::create_dir_all(full_path.parent().unwrap())?;

        info!("decrypting {}", full_path.as_path().to_string_lossy());

        let mut opts = OpenOptions::new();

        opts.write(true).create_new(true);

        if cfg!(unix) {
            opts.mode(0o600);
        }

        let mut out = opts.open(full_path)?;

        let mut offset : u64 = 0;

        let len = file.length;

        while offset < len {
            let to_read = std::cmp::min(read_buffer.len(), (len - offset) as usize);
            let read = input.read(&mut read_buffer[..to_read])?;

            offset += read as u64;

            payload_cipher.xor_read(&mut read_buffer);

            out.write_all(&read_buffer[..read])?;
        }
    }


    Ok(())

}
