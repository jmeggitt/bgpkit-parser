/*!
parser module maintains the main logic for processing BGP and MRT messages.
*/
use std::io::Read;

#[macro_use]
pub mod utils;
pub mod bgp;
pub mod bmp;
pub mod filter;
pub mod iters;
pub mod mrt;

#[cfg(feature = "rislive")]
pub mod rislive;

pub(crate) use self::utils::*;
pub(crate) use bgp::attributes::AttributeParser;
pub(crate) use mrt::{parse_bgp4mp, parse_table_dump_message, parse_table_dump_v2_message};

use crate::models::MrtRecord;
use filter::Filter;
pub use mrt::mrt_elem::Elementor;
use oneio::{get_cache_reader, get_reader, OneIoError};

pub use crate::error::ParserError;
pub use bmp::{parse_bmp_msg, parse_openbmp_header, parse_openbmp_msg};
pub use filter::*;
pub use iters::*;
pub use mrt::*;

#[cfg(feature = "rislive")]
pub use rislive::parse_ris_live_message;

pub struct BgpkitParser<R> {
    reader: R,
    core_dump: bool,
    filters: Vec<Filter>,
    options: ParserOptions,
}

pub(crate) struct ParserOptions {
    show_warnings: bool,
}
impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions {
            show_warnings: true,
        }
    }
}

impl BgpkitParser<Box<dyn Read + Send>> {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn new(path: &str) -> Result<Self, OneIoError> {
        let reader = get_reader(path)?;
        Ok(BgpkitParser {
            reader,
            core_dump: false,
            filters: vec![],
            options: ParserOptions::default(),
        })
    }

    /// Creating a new parser that also caches the remote content to a local cache directory.
    ///
    /// The cache file name is generated by the following format: `cache-<crc32 of file name>-<file name>`.
    /// For example, the remote file `http://archive.routeviews.org/route-views.chile/bgpdata/2023.03/RIBS/rib.20230326.0600.bz2`
    /// will be cached as `cache-682cb1eb-rib.20230326.0600.bz2` in the cache directory.
    pub fn new_cached(path: &str, cache_dir: &str) -> Result<Self, OneIoError> {
        let file_name = path.rsplit('/').next().unwrap().to_string();
        let new_file_name = format!(
            "cache-{}",
            add_suffix_to_filename(file_name.as_str(), crc32(path).as_str())
        );
        let reader = get_cache_reader(path, cache_dir, Some(new_file_name), false)?;
        Ok(BgpkitParser {
            reader,
            core_dump: false,
            filters: vec![],
            options: ParserOptions::default(),
        })
    }
}

fn add_suffix_to_filename(filename: &str, suffix: &str) -> String {
    let mut parts: Vec<&str> = filename.split('.').collect(); // Split filename by dots
    if parts.len() > 1 {
        let last_part = parts.pop().unwrap(); // Remove the last part (suffix) from the parts vector
        let new_last_part = format!("{}.{}", suffix, last_part); // Add the suffix to the last part
        parts.push(&new_last_part); // Add the updated last part back to the parts vector
        parts.join(".") // Join the parts back into a filename string with dots
    } else {
        // If the filename does not have any dots, simply append the suffix to the end
        format!("{}.{}", filename, suffix)
    }
}

/// A CRC32 implementation that converts a string to a hex string.
///
/// CRC32 is a checksum algorithm that is used to verify the integrity of data. It is short in
/// length and sufficient for generating unique file names based on remote URLs.
pub fn crc32(input: &str) -> String {
    let input_bytes = input.as_bytes();
    let mut table = [0u32; 256];
    let polynomial = 0xedb88320u32;

    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }

    let mut crc = !0u32;
    for byte in input_bytes.iter() {
        let index = ((crc ^ (*byte as u32)) & 0xff) as usize;
        crc = (crc >> 8) ^ table[index];
    }

    format!("{:08x}", !crc)
}

impl<R: Read> BgpkitParser<R> {
    /// Creating a new parser from a object that implements [Read] trait.
    pub fn from_reader(reader: R) -> Self {
        BgpkitParser {
            reader,
            core_dump: false,
            filters: vec![],
            options: ParserOptions::default(),
        }
    }

    /// This is used in for loop `for item in parser{}`
    pub fn next_record(&mut self) -> Result<Option<MrtRecord>, ParserError> {
        try_parse_mrt_record(&mut self.reader)
    }
}

impl<R> BgpkitParser<R> {
    pub fn enable_core_dump(self) -> Self {
        BgpkitParser {
            reader: self.reader,
            core_dump: true,
            filters: self.filters,
            options: self.options,
        }
    }

    pub fn disable_warnings(self) -> Self {
        let mut options = self.options;
        options.show_warnings = false;
        BgpkitParser {
            reader: self.reader,
            core_dump: self.core_dump,
            filters: self.filters,
            options,
        }
    }

    pub fn add_filter(mut self, filter: Filter) -> Self {
        self.filters.push(filter);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_reader() {
        // bzip2 reader for compressed file
        let http_stream = ureq::get("http://archive.routeviews.org/route-views.ny/bgpdata/2023.02/UPDATES/updates.20230215.0630.bz2")
            .call().unwrap().into_reader();
        let reader = bzip2::read::BzDecoder::new(http_stream);
        assert_eq!(
            12683,
            BgpkitParser::from_reader(reader).into_elem_iter().count()
        );

        // remote reader for uncompressed updates file
        let reader = ureq::get("https://spaces.bgpkit.org/parser/update-example")
            .call()
            .unwrap()
            .into_reader();
        assert_eq!(
            8160,
            BgpkitParser::from_reader(reader).into_elem_iter().count()
        );
    }
}
