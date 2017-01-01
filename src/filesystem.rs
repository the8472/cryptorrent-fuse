extern crate time;
extern crate libc;
extern crate multimap;
extern crate bip_bencode;
extern crate walkdir;
extern crate rustc_serialize;

use fuse::*;
use std::path::*;
use std::os;
use std::io::{Read,Seek, SeekFrom};
use self::libc::{ENOENT, ENOSYS};
use self::time::Timespec;
use self::multimap::MultiMap;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use self::walkdir::WalkDir;
use self::bip_bencode::*;
use self::bip_bencode::Bencode::*;
use std::io::BufReader;
use std::io::BufRead;
use self::rustc_serialize::hex::*;
use std::ffi::{OsString};
use super::DecryptedMeta;
use chacha::*;


struct Inode {
    parent: u64,
    name : OsString,
    torrent_idx : i64,
    file_idx : i64,
    depth : i64,
    attrs : FileAttr

}

pub struct CryptorrentFs {
    keys: Vec<Vec<u8>>,
    source_dirs: Vec<PathBuf>,
    torrents: Vec<PathBuf>,
    meta: Vec<DecryptedMeta>,
    children: MultiMap<u64, u64>,
    inodes: BTreeMap<u64, Inode>
}



impl CryptorrentFs {
    pub fn new() -> CryptorrentFs {
        let mut fs = CryptorrentFs {keys: vec![], torrents: vec![], source_dirs: vec![], meta: vec![], children: MultiMap::new(), inodes: BTreeMap::new() };

        // root dir

        let root = Inode {
            parent: 0,
            name: OsString::new(),
            torrent_idx: -1,
            file_idx: -1,
            depth: -1,
            attrs: FileAttr {
                ino: FUSE_ROOT_ID,
                size: 0,
                blocks: 0,
                atime: Timespec::new(0, 0),
                mtime: Timespec::new(0, 0),
                ctime: Timespec::new(0, 0),
                crtime: Timespec::new(0, 0),
                kind: FileType::Directory,
                perm: 0o500,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0
            }
        };

        fs.inodes.insert(FUSE_ROOT_ID,root);


        fs


    }

    pub fn add_keyfile(&mut self, path: &str) -> Result<(), Box<super::std::error::Error>> {
        let f = File::open(path).unwrap();
        let mut buf = BufReader::new(&f);
        for line in buf.lines() {
            let key = line.unwrap().from_hex()?;
            self.keys.push(key)
        }

        Ok(())
    }

    pub fn add_source_dir(&mut self, path: &str) {
        self.source_dirs.push(PathBuf::from(path));

        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|dent| dent.file_type().is_file() && dent.metadata().unwrap().len() < 50*1024*1024) {
            self.add_torrent(entry.path())
        }

    }

    fn next_id(&self) -> u64 {
        self.inodes.keys().rev().next().unwrap_or(&1) + 1
    }

    fn add_torrent(&mut self, path: &Path) {

        let decr = {
            let iter = self.keys.iter().map(Vec::as_slice);
            super::DecryptedMeta::new(&path.to_string_lossy(), iter)
        };

        if let Ok(mut meta) = decr {

            let cipher_length = meta.length;
            for entry in WalkDir::new(path.parent().unwrap()).into_iter().filter_map(|e| e.ok()).filter(|dent| dent.file_type().is_file() && dent.metadata().unwrap().len() == cipher_length) {
                // TODO: hash-check
                meta.ciphertext = Some(entry.path().to_owned())
            }


            let idx = self.meta.len();

            let torrent_root_id = self.next_id();

            let torrent_idx = self.torrents.len() as i64;

            debug!("torrents {:?}", self.torrents);
            debug!("appending torrent #{} #{}", idx, torrent_idx);


            let name = meta.name.iter().next().unwrap().to_owned();


            let attrs = FileAttr {
                ino: torrent_root_id,
                size: 0,
                blocks: 0,
                atime: Timespec::new(0, 0),
                mtime: Timespec::new(0, 0),
                ctime: Timespec::new(0, 0),
                crtime: Timespec::new(0, 0),
                kind: FileType::Directory,
                perm: 0o500,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0
            };

            let node = Inode {
                parent: FUSE_ROOT_ID,
                name: name,
                torrent_idx: torrent_idx,
                file_idx: -1,
                depth: 0,
                attrs: attrs
            };

            self.inodes.insert(torrent_root_id, node);
            self.children.insert(FUSE_ROOT_ID, torrent_root_id);

            for (i,ref f) in meta.plaintext_files.iter().enumerate() {

                let file_path = &f.path;
                let file_id = self.next_id();


                let parent = self.mkdirs(torrent_root_id, file_path);

                let attrs = FileAttr {
                    ino: file_id,
                    size: f.length,
                    blocks: 0,
                    atime: Timespec::new(0, 0),
                    mtime: Timespec::new(0, 0),
                    ctime: Timespec::new(0, 0),
                    crtime: Timespec::new(0, 0),
                    kind: FileType::RegularFile,
                    perm: 0o400,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0
                };

                let node = Inode {
                    parent: parent,
                    name: file_path.file_name().unwrap().to_owned(),
                    torrent_idx: torrent_idx,
                    file_idx: i as i64,
                    depth: 0,
                    attrs: attrs
                };

                self.inodes.insert(file_id, node);
                self.children.insert(parent, file_id);


            }

            self.meta.push(meta);
            let p = PathBuf::from(path);

            self.torrents.push(p);

        }





    }

    fn get(&self, parent: u64, name: &OsStr) -> Option<u64> {
        if let Some(vec) = self.children.get_vec(&parent) {
            for &child_id in vec {
                if let Some(child) = self.inodes.get(&child_id) {
                    if child.name == name {
                        return Some(child.attrs.ino);
                    }
                }
            }
        }

        None
    }

    fn mkdirs(&mut self, root: u64, path : &Path) -> u64 {
        let mut p = root;

        let root_idx = {
            let r = self.inodes.get(&root).unwrap();
            r.torrent_idx
        };

        if let Some(prefix) = path.parent() {
            for element in prefix {
                match self.get(p, element) {
                    Some(ref inode) => {
                        p = self.inodes.get(&inode).unwrap().attrs.ino
                    },
                    None => {

                        let id = self.next_id();

                        let attrs = FileAttr {
                            ino: id,
                            size: 0,
                            blocks: 0,
                            atime: Timespec::new(0, 0),
                            mtime: Timespec::new(0, 0),
                            ctime: Timespec::new(0, 0),
                            crtime: Timespec::new(0, 0),
                            kind: FileType::Directory,
                            perm: 0o500,
                            nlink: 1,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            flags: 0
                        };

                        let node = Inode {
                            parent: p,
                            name: element.to_owned(),
                            torrent_idx: root_idx,
                            file_idx: -1,
                            depth: 0,
                            attrs: attrs
                        };

                        self.inodes.insert(id, node);
                        self.children.insert(p, id);

                        p = id

                    }

                }

            }

        }

        p

    }

}

impl Filesystem for CryptorrentFs {

    fn lookup(&mut self, _req: &Request, parent_ino: u64, _name: &Path, reply: ReplyEntry) {
        println!("lookup {} {:?} {:?}", parent_ino, _name, reply);

        if let Some(parent) = self.inodes.get(&parent_ino) {
            if _name == Path::new(".") {
                reply.entry(&Timespec::new(1, 0), &parent.attrs, 1);
                return;
            }

            if let Some(child) = self.get(parent_ino, _name.iter().next().unwrap()) {
                reply.entry(&Timespec::new(1, 0), &self.inodes.get(&child).unwrap().attrs, 1);
                return;
            }

        } else {
            reply.error(ENOENT);
            return;
        }


        reply.error(ENOENT);
    }

    fn read(&mut self, _req: &Request, _ino: u64, _fh: u64, _offset: u64, _size: u32, reply: ReplyData) {
        if let Some(inode) = self.inodes.get(&_ino) {
            let ref meta = self.meta[inode.torrent_idx as usize];
            let ref tf = meta.plaintext_files[inode.file_idx as usize];
            let ref keys = meta.keys;
            let piece_space_offset = _offset + tf.offset;

            let p = meta.ciphertext.as_ref().unwrap();
            let mut f = File::open(p).unwrap();

            f.seek(SeekFrom::Start(piece_space_offset)).unwrap();

            let to_read = super::std::cmp::min(_size, (tf.length - _offset) as u32);

            let mut buf = vec![0 ; to_read as usize];

            f.read_exact(&mut buf).unwrap();

            let mut cipher = keys.seekable_payload_cipher();
            cipher.seek_to(piece_space_offset).unwrap();
            cipher.xor_read(&mut buf).unwrap();

            reply.data(&buf);
            return;
        }

        reply.error(ENOENT);
    }

    fn readdir(&mut self, _req: &Request, ino: u64, fh: u64, offset: u64, mut reply: ReplyDirectory) {
        match self.inodes.get(&ino)  {
            Some(inode) => {
                if offset == 0 {
                    //reply.add(inode.parent, 0, FileType::Directory, "..");
                    reply.add(inode.attrs.ino, 1, FileType::Directory, ".");
                }

                if let Some(vec) = self.children.get_vec(&ino) {
                    for i in 0 .. vec.len() {
                        if i + 1 < offset as usize {
                            continue;
                        }


                        let child_ino = vec[i];
                        let child = self.inodes.get(&child_ino).unwrap();
                        if reply.add(child_ino, 2 + i as u64, child.attrs.kind, &child.name) {
                            break;
                        }
                    }
                }
                reply.ok()
            },
            None => reply.error(ENOSYS)
        }


        println!("readdir(ino={}, fh={}, offset={})", ino, fh, offset);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        println!("getattr(ino={})", ino);

        match self.inodes.get(&ino) {
            Some(i) => {
                reply.attr(&Timespec::new(1, 0), &i.attrs);
            }
            None => reply.error(ENOSYS)
        }
    }



}