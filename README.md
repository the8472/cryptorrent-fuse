# cryptorrent-fuse

CLI tool and FUSE driver to apply storage-layer encryption to torrents.
The process is transparent to torrent clients not supporting this extension, they simply transfer the encrypted data

## Experimental Status

* The BEP for this extension is not finalized
* it is a prototype (some parts are slow, many rough corners)
* not all potential error cases are handled. the application may just abort or return nonsense-data

## requirements

* rust, cargo
* libfuse

## build

```
git clone https://github.com/the8472/cryptorrent-fuse.git .
cargo build --release
./target/release/cryptorrent --help
```

## example use

```
# create torrent and encrypted file. prints keys to stdout
cryptorrent create /dir/to/encrypt /outputdir
echo "<key>" > keyfile

# mount all torrents for which we have keys and ciphertext files
cryptorrent-fuse /mountpount /outputdir keyfile

# decrypt
cryptorrent decrypt encrypted.torrent ciphertext.file /outputdir

# decrypt shadow data
cryptorrent shadow encrypted.torrent


```