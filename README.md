# LOX Archive Format

LOX is a custom streaming archive format that combines:

- **AEAD encryption (XChaCha20-Poly1305)**
- **XZ compression**
- **TAR archival format**

It is designed for chunked streaming encryption with compression layered between encryption and archival.

---

## Pipeline Overview

### Encoding flow

```

File/Dir → TAR → XZ → AEAD (chunked) → Output

```

### Decoding flow

```

Input → AEAD Reader → XZ Decoder → TAR Archive → Files

```

---

## Features

- Chunk-based encrypted streaming (AEAD)
- Random nonce per chunk
- XZ compression layer
- TAR-compatible archive structure
- Streaming read/write (no full buffering required)
- Directory and file support

---

## Chunk Format

Each encrypted chunk is written as:

```

[nonce (24 bytes)]
[chunk_length (u64 LE)]
[ciphertext]
[tag (16 bytes)]

````

- Nonce: generated per chunk
- Length: plaintext size before encryption
- Ciphertext: encrypted data
- Tag: authentication tag

---

## Usage Example

### Encoding

```rust
use std::fs::File;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;

use lox::Encoder;

fn main() {
    let mut rng = OsRng;
    let key = XChaCha20Poly1305::generate_key(&mut rng);
    let cipher = XChaCha20Poly1305::new(&key);

    let out = File::create("archive.lox").unwrap();

    let mut encoder = Encoder::new(
        out,
        cipher,
        rng,
        1024 * 512,
        b"associated-data",
        6,
    );

    encoder.append_dir_all("backup", "./data").unwrap();
    encoder.finish().unwrap();
}
````

---

### Decoding

```rust
use std::fs::File;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};

use lox::Decoder;

fn main() {
    let key = /* same key used for encryption */;
    let cipher = XChaCha20Poly1305::new(&key);

    let input = File::open("archive.lox").unwrap();

    let mut decoder = Decoder::new(
        input,
        cipher,
        b"associated-data",
    );

    decoder.unpack("output").unwrap();
}
```

---

## Architecture

### Encoder stack

```
TAR Builder
   ↓
XZ Encoder
   ↓
AEAD Chunk Writer
   ↓
Write Sink
```

### Decoder stack

```
Read Sink
   ↓
AEAD Chunk Reader
   ↓
XZ Decoder
   ↓
TAR Extractor
```

---

## Notes

* Each chunk is independently encrypted
* Nonce is generated per chunk
* Compression happens before encryption (important for security + efficiency)
* `finish()` must be called to properly finalize XZ stream
* Missing finalization may cause `UnexpectedEof` during decode

---

## Status

This project is experimental and used for:

* learning streaming codecs
* encryption + compression layering
* archive format design exploration

---

## Future ideas

* incremental verification
* chunk resumption / partial recovery
* parallel encoding
* format versioning header
* integrity manifest (file-level hash tree)

---

## License

MIT

