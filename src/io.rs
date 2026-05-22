use std::io::{Error, ErrorKind, Read, Result, Write};

pub const MAX_CHUNK_SIZE: usize = 1024 * 1024 * 8; // 8 MiB

use aead::{
    AeadCore, AeadInPlace,
    generic_array::GenericArray,
    rand_core::{CryptoRng, RngCore},
};

pub struct Writer<'a, W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    inner: W,
    chunk_size: usize,
    buffer: Vec<u8>,
    cipher: C,
    ad: &'a [u8],
    rng: R,
}

impl<'a, W, C, R> Writer<'a, W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    pub fn new(inner: W, cipher: C, rng: R, chunk_size: usize, ad: &'a [u8]) -> Self {
        let buffer = Vec::with_capacity(chunk_size);
        Self {
            ad,
            inner,
            chunk_size,
            buffer,
            cipher,
            rng,
        }
    }

    fn flush_chunk(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let nonce = C::generate_nonce(&mut self.rng);

        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, self.ad, &mut self.buffer)
            .map_err(|_| Error::other("encryption failed"))?;

        self.inner.write_all(&nonce)?;

        let buf_len = self.buffer.len() as u64;
        self.inner.write_all(&buf_len.to_le_bytes())?;

        self.inner.write_all(&self.buffer)?;

        self.inner.write_all(&tag)?;

        self.buffer.clear();
        Ok(())
    }
}

impl<'a, W, C, R> Write for Writer<'a, W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut rem = self.chunk_size - self.buffer.len();
        if rem == 0 {
            self.flush_chunk()?;
            rem = self.chunk_size - self.buffer.len();
        };
        let take = rem.min(buf.len());
        self.buffer.extend_from_slice(&buf[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_chunk()?;
        self.inner.flush()
    }
}

pub struct Reader<'a, R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    cipher: C,
    inner: R,
    ad: &'a [u8],
    buffer: Vec<u8>,
    pos: usize,
}

impl<'a, R, C> Reader<'a, R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    pub fn new(inner: R, cipher: C, ad: &'a [u8]) -> Self {
        Self {
            cipher,
            inner,
            ad,
            buffer: Vec::new(),
            pos: 0,
        }
    }

    fn fill_buffer_replaced(&mut self) -> Result<usize> {
        let mut nonce = GenericArray::<u8, C::NonceSize>::default();
        let mut readn = 0usize;

        while readn < nonce.len() {
            let n = self.inner.read(&mut nonce[readn..])?;
            if n == 0 {
                break;
            }
            readn += n;
        }
        if readn == 0 {
            return Ok(0);
        }
        if readn != nonce.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "chunk truncated"));
        }

        let mut len_buf = [0u8; 8];
        self.inner.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;

        if len > MAX_CHUNK_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "invalid chunk size"));
        };

        self.buffer.clear();
        self.buffer.reserve(len);
        self.buffer.resize(len, 0);

        self.inner.read_exact(&mut self.buffer)?;

        let mut tag = GenericArray::<u8, C::TagSize>::default();
        self.inner.read_exact(&mut tag)?;

        self.cipher
            .decrypt_in_place_detached(&nonce, self.ad, &mut self.buffer, &tag)
            .map_err(|_| Error::other("decryption failed"))?;

        self.pos = 0;
        Ok(self.buffer.len())
    }
}

impl<'a, R, C> Read for Reader<'a, R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pos >= self.buffer.len() {
            let filled = self.fill_buffer_replaced()?;
            if filled == 0 {
                return Ok(0);
            };
        };
        let take = self.buffer[self.pos..].len().min(buf.len());
        if take == 0 {
            return Ok(0);
        };
        buf[..take].copy_from_slice(&self.buffer[self.pos..self.pos + take]);
        self.pos += take;
        Ok(take)
    }
}
