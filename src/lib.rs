mod io;

use std::{
    fs::File,
    io::{Read, Result, Write},
    path::Path,
};

use aead::{
    AeadCore, AeadInPlace,
    rand_core::{CryptoRng, RngCore},
};
use tar::{Archive, Builder};
use xz2::{read::XzDecoder, write::XzEncoder};

use crate::io::{Reader, Writer};

type EncWriter<'a, W, C, R> = Writer<'a, W, C, R>;
type XzWriter<'a, W, C, R> = XzEncoder<EncWriter<'a, W, C, R>>;
type TarWriter<'a, W, C, R> = Builder<XzWriter<'a, W, C, R>>;

pub struct Encoder<'a, W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    inner: TarWriter<'a, W, C, R>,
}

impl<'a, W, C, R> Encoder<'a, W, C, R>
where
    W: Write,
    C: AeadCore + AeadInPlace,
    R: RngCore + CryptoRng,
{
    pub fn new(
        inner: W,
        cipher: C,
        rng: R,
        chunk_size: usize,
        ad: &'a [u8],
        compress_level: u32,
    ) -> Self {
        let enc_writer = EncWriter::new(inner, cipher, rng, chunk_size, ad);
        let xz_writer = XzWriter::new(enc_writer, compress_level);
        let inner = TarWriter::new(xz_writer);
        Self { inner }
    }

    pub fn append_dir<P, Q>(&mut self, path: P, src_path: Q) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self.inner.append_dir(path, src_path)
    }

    pub fn append_dir_all<P, Q>(&mut self, dst: P, src: Q) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self.inner.append_dir_all(dst, src)
    }

    pub fn append_file<P>(&mut self, path: P, file: &mut File) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.append_file(path, file)
    }

    pub fn append_path<P>(&mut self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.append_path(path)
    }

    pub fn append_path_with_name<P, N>(&mut self, path: P, name: N) -> Result<()>
    where
        P: AsRef<Path>,
        N: AsRef<Path>,
    {
        self.inner.append_path_with_name(path, name)
    }

    pub fn finish(self) -> Result<()> {
        let xz_writer = self.inner.into_inner()?;
        let mut enc_writer = xz_writer.finish()?;
        enc_writer.flush()?;
        Ok(())
    }
}

type DecReader<'a, R, C> = Reader<'a, R, C>;
type XzReader<'a, R, C> = XzDecoder<DecReader<'a, R, C>>;
type TarReader<'a, R, C> = Archive<XzReader<'a, R, C>>;

pub struct Decoder<'a, R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    inner: TarReader<'a, R, C>,
}

impl<'a, R, C> Decoder<'a, R, C>
where
    R: Read,
    C: AeadCore + AeadInPlace,
{
    pub fn new(inner: R, cipher: C, ad: &'a [u8]) -> Self {
        let dec_reader = DecReader::new(inner, cipher, ad);
        let xz_reader = XzReader::new(dec_reader);
        let inner = TarReader::new(xz_reader);
        Self { inner }
    }

    pub fn unpack<P>(&mut self, dst: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.unpack(dst)
    }
}
