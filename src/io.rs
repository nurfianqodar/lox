use std::io::{Error, ErrorKind, Read, Result, Write};

pub const MAX_CHUNK_SIZE: usize = 1024 * 1024 * 8; // 8 MiB

use aead::{
    AeadCore, AeadInPlace,
    generic_array::GenericArray,
    rand_core::{CryptoRng, RngCore},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Writer<W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    #[zeroize(skip)]
    inner: W,
    #[zeroize(skip)]
    cipher: C,
    #[zeroize(skip)]
    rng: R,
    ad: Vec<u8>,
    chunk_size: usize,
    buffer: Vec<u8>,
}

impl<W, C, R> Writer<W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    pub fn new(inner: W, cipher: C, rng: R, chunk_size: usize, ad: &[u8]) -> Self {
        let buffer = Vec::with_capacity(chunk_size);
        Self {
            ad: ad.to_vec(),
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
            .encrypt_in_place_detached(&nonce, &self.ad, &mut self.buffer)
            .map_err(|_| Error::other("encryption failed"))?;
        let buf_len = u64::try_from(self.buffer.len())
            .map_err(|_| Error::new(ErrorKind::InvalidData, "unable to convert usize to u64"))?;

        self.inner.write_all(&nonce)?;
        self.inner.write_all(&buf_len.to_le_bytes())?;
        self.inner.write_all(&self.buffer)?;
        self.inner.write_all(&tag)?;

        self.buffer.clear();
        Ok(())
    }
}

impl<'a, W, C, R> Write for Writer<W, C, R>
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Reader<R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    #[zeroize(skip)]
    cipher: C,
    #[zeroize(skip)]
    inner: R,
    ad: Vec<u8>,
    buffer: Vec<u8>,
    pos: usize,
}

impl<R, C> Reader<R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    pub fn new(inner: R, cipher: C, ad: &[u8]) -> Self {
        Self {
            cipher,
            inner,
            ad: ad.to_vec(),
            buffer: Vec::new(),
            pos: 0,
        }
    }

    /// fill buffer with new decrypted data
    /// return the length of decrypted data
    ///
    /// Note: remaining content will overwrited make sure no
    /// remaining buffer in the buffer
    fn fill_buffer_replaced(&mut self) -> Result<usize> {
        let mut nonce = GenericArray::<u8, C::NonceSize>::default();
        let mut readn = 0usize;
        while readn < nonce.len() {
            // read nonce or EOF on 0 result
            let n = self.inner.read(&mut nonce[readn..])?;
            if n == 0 {
                if readn == 0 {
                    return Ok(0); // EOF
                };
                if readn != nonce.len() {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "chunk truncated"));
                };
                break;
            };
            readn += n;
        }

        let mut len_buf = [0u8; 8];
        self.inner.read_exact(&mut len_buf)?;
        let len = usize::try_from(u64::from_le_bytes(len_buf))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "unable to convert u64 to usize"))?;
        if len > MAX_CHUNK_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "invalid chunk size"));
        };

        self.buffer.clear();
        self.buffer.reserve(len);
        self.buffer.resize(len, 0);

        let mut tag = GenericArray::<u8, C::TagSize>::default();

        self.inner.read_exact(&mut self.buffer)?;
        self.inner.read_exact(&mut tag)?;

        self.cipher
            .decrypt_in_place_detached(&nonce, &self.ad, &mut self.buffer, &tag)
            .map_err(|_| Error::other("decryption failed"))?;
        self.pos = 0; // reset cursor position to 0

        Ok(self.buffer.len())
    }
}

impl<R, C> Read for Reader<R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    /// read decrypted data to a buffer, return length
    /// of filled buffer
    ///
    /// partial read may always happen so use read_exact
    /// to avoid partial read
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
