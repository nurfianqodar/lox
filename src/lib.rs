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
    /// Creates a streaming archive encoder.
    ///
    /// Parameters
    ///
    /// - `inner`: output writer.
    /// - `cipher`: AEAD cipher used for encryption.
    /// - `rng`: secure RNG for nonce generation.
    /// - `chunk_size`: encrypted chunk size in bytes.
    /// - `ad`: additional authenticated data (AAD).
    /// - `compress_level`: xz compression level (`0..=9`).
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

    /// Adds a directory to this archive with the given path as the name of
    /// the directory in the archive.
    ///
    /// This will use stat to populate a Header, and it will then append the
    /// directory to the archive with the name path.
    ///
    /// Note that this will not attempt to seek the archive to a valid position,
    /// so if the archive is in the middle of a read or some other similar
    /// operation then this may corrupt the archive.
    ///
    /// Note this will not add the contents of the directory to the archive.
    /// See append_dir_all for recursively adding the contents of the directory.
    ///
    /// Also note that after all files have been written to an archive the finish
    /// function needs to be called to finish writing the archive.
    pub fn append_dir<P, Q>(&mut self, path: P, src_path: Q) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self.inner.append_dir(path, src_path)
    }

    /// Adds a directory and all of its contents (recursively) to this archive
    /// with the given path as the name of the directory in the archive.
    ///
    /// Note that this will not attempt to seek the archive to a valid position,
    /// so if the archive is in the middle of a read or some other similar
    /// operation then this may corrupt the archive.
    ///
    /// Also note that after all files have been written to an archive the finish
    /// or into_inner function needs to be called to finish writing the archive.
    pub fn append_dir_all<P, Q>(&mut self, dst: P, src: Q) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self.inner.append_dir_all(dst, src)
    }

    /// Adds a file to this archive with the given path as the name of the
    /// file in the archive.
    ///
    /// This will use the metadata of file to populate a Header, and it will
    /// then append the file to the archive with the name path.
    ///
    /// Note that this will not attempt to seek the archive to a valid position,
    /// so if the archive is in the middle of a read or some other similar
    /// operation then this may corrupt the archive.
    ///
    /// Also note that after all files have been written to an archive the finish
    /// function needs to be called to finish writing the archive.
    pub fn append_file<P>(&mut self, path: P, file: &mut File) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.append_file(path, file)
    }

    /// Adds a file on the local filesystem to this archive.
    ///
    /// This function will open the file specified by path and insert
    /// the file into the archive with the appropriate metadata set,
    /// returning any I/O error which occurs while writing. The path
    /// name for the file inside of this archive will be the same as
    /// path, and it is required that the path is a relative path.
    ///
    /// Note that this will not attempt to seek the archive to a valid
    /// position, so if the archive is in the middle of a read or some
    /// other similar operation then this may corrupt the archive.
    ///
    /// Also note that after all files have been written to an archive
    /// the finish function needs to be called to finish writing the archive.
    pub fn append_path<P>(&mut self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.append_path(path)
    }

    /// Adds a file on the local filesystem to this archive under another name.
    ///
    /// This function will open the file specified by path and insert the file
    /// into the archive as name with appropriate metadata set, returning any
    /// I/O error which occurs while writing. The path name for the file inside
    /// of this archive will be name is required to be a relative path.
    ///
    /// Note that this will not attempt to seek the archive to a valid position,
    /// so if the archive is in the middle of a read or some other similar
    /// operation then this may corrupt the archive.
    ///
    /// Note if the path is a directory. This will just add an entry to the archive,
    /// rather than contents of the directory.
    ///
    /// Also note that after all files have been written to an archive the finish
    /// function needs to be called to finish writing the archive.
    pub fn append_path_with_name<P, N>(&mut self, path: P, name: N) -> Result<()>
    where
        P: AsRef<Path>,
        N: AsRef<Path>,
    {
        self.inner.append_path_with_name(path, name)
    }

    /// Finish writing this archive, emitting the termination sections.
    ///
    /// This function should only be called when the archive has been
    /// written entirely
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
    /// Creates a streaming archive decoder.
    ///
    /// Parameters
    ///
    /// - `inner`: encrypted input reader.
    /// - `cipher`: AEAD cipher used for decryption.
    /// - `ad`: additional authenticated data (AAD).
    pub fn new(inner: R, cipher: C, ad: &'a [u8]) -> Self {
        let dec_reader = DecReader::new(inner, cipher, ad);
        let xz_reader = XzReader::new(dec_reader);
        let inner = TarReader::new(xz_reader);
        Self { inner }
    }

    /// Set the mask of the permission bits when unpacking this entry.
    ///
    /// The mask will be inverted when applying against a mode, similar
    /// to how umask works on Unix.
    /// The mask is 0 by default and is currently only implemented on
    /// Unix.
    pub fn set_mask(&mut self, mask: u32) {
        self.inner.set_mask(mask);
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are
    /// preserved when unpacking this archive.
    ///
    /// This flag is disabled by default and is currently only implemented
    /// on Unix using xattr support. This may eventually be implemented
    /// for Windows, however, if other archive implementations are found
    /// which do this as well.
    pub fn set_unpack_xattrs(&mut self, unpack_xattrs: bool) {
        self.inner.set_unpack_xattrs(unpack_xattrs);
    }

    /// Indicate whether extended permissions (like suid on Unix) are
    /// preserved when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented
    /// on Unix.   
    pub fn set_preserve_permissions(&mut self, preserve: bool) {
        self.inner.set_preserve_permissions(preserve);
    }

    /// Indicate whether numeric ownership ids (like uid and gid on Unix)
    /// are preserved when unpacking this entry.

    /// This flag is disabled by default and is currently only implemented
    /// on Unix.
    pub fn set_preserve_ownerships(&mut self, preserve: bool) {
        self.inner.set_preserve_ownerships(preserve);
    }

    /// Indicate whether files and symlinks should be overwritten on
    /// extraction.
    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.inner.set_overwrite(overwrite);
    }

    /// Indicate whether access time information is preserved when
    /// unpacking this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(&mut self, preserve: bool) {
        self.inner.set_preserve_mtime(preserve);
    }

    /// Ignore zeroed headers, which would otherwise indicate to the archive
    /// that it has no more entries.
    ///
    /// This can be used in case multiple tar archives have been concatenated
    /// together.
    pub fn set_ignore_zeros(&mut self, ignore_zeros: bool) {
        self.inner.set_ignore_zeros(ignore_zeros);
    }

    /// Unpacks the contents archive into the specified dst.
    ///
    /// This function will iterate over the entire contents of this
    /// archive extracting each file in turn to the location specified
    /// by the entry’s path name.
    pub fn unpack<P>(&mut self, dst: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.inner.unpack(dst)
    }
}
