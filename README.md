# LOX Archive

LOX is a custom streaming archive format. It is designed for chunked
streaming encryption with compression layered between encryption and
archival.

## Features

- Chunk-based encrypted streaming (AEAD)
- Compression layer
- Streaming read/write (no full buffering required)
- Directory and file support

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

## License

MIT

