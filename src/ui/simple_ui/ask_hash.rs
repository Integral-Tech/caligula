use std::{
    fs::File,
    io::{BufRead, BufReader, Seek},
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{anyhow, Context};
use bytesize::ByteSize;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, Select, Text};

use crate::{
    compression::{decompress, CompressionFormat},
    hash::{parse_hash_input, FileHashInfo, HashAlg, Hashing},
    ui::cli::{BurnArgs, HashArg, HashOf},
};

/// Common filenames of hash files.
const HASH_FILES: [(HashAlg, &str); 24] = [
    (HashAlg::Md5, "md5sum.txt"),
    (HashAlg::Md5, "md5sums.txt"),
    (HashAlg::Md5, "MD5SUM"),
    (HashAlg::Md5, "MD5SUMS"),
    (HashAlg::Sha1, "sha1sum.txt"),
    (HashAlg::Sha1, "sha1sums.txt"),
    (HashAlg::Sha1, "SHA1SUM"),
    (HashAlg::Sha1, "SHA1SUMS"),
    (HashAlg::Sha224, "sha224sum.txt"),
    (HashAlg::Sha224, "sha224sums.txt"),
    (HashAlg::Sha224, "SHA224SUM"),
    (HashAlg::Sha224, "SHA224SUMS"),
    (HashAlg::Sha256, "sha256sum.txt"),
    (HashAlg::Sha256, "sha256sums.txt"),
    (HashAlg::Sha256, "SHA256SUM"),
    (HashAlg::Sha256, "SHA256SUMS"),
    (HashAlg::Sha384, "sha384sum.txt"),
    (HashAlg::Sha384, "sha384sums.txt"),
    (HashAlg::Sha384, "SHA384SUM"),
    (HashAlg::Sha384, "SHA384SUMS"),
    (HashAlg::Sha512, "sha512sum.txt"),
    (HashAlg::Sha512, "sha512sums.txt"),
    (HashAlg::Sha512, "SHA512SUM"),
    (HashAlg::Sha512, "SHA512SUMS"),
];

#[tracing::instrument(skip_all, fields(cf))]
pub fn ask_hash(args: &BurnArgs, cf: CompressionFormat) -> anyhow::Result<Option<FileHashInfo>> {
    let hash_params = match &args.hash {
        HashArg::Skip => None,
        HashArg::Ask => {
            match find_hash(&args.input) {
                Some((alg, expected_hashfile, expected_hash))
                if Confirm::new(&format!(
                    "Detected hash file {expected_hashfile} in the directory. Do you want to use it?"
                ))
                .with_default(true)
                .prompt()? =>
                    Some(BeginHashParams {
                        expected_hash,
                        alg,
                        hasher_compression: ask_hasher_compression(cf, args.hash_of)?,
                    }),
                _ => ask_hash_loop(cf)?
            }
        }
        HashArg::Hash { alg, expected_hash } => Some(BeginHashParams {
            expected_hash: expected_hash.clone(),
            alg: alg.clone(),
            hasher_compression: ask_hasher_compression(cf, args.hash_of)?,
        }),
    };

    let params = if let Some(p) = hash_params {
        p
    } else {
        return Ok(None);
    };

    let hash_result = do_hashing(&args.input, &params)?;

    if hash_result.file_hash == params.expected_hash {
        eprintln!("Disk image verified successfully!");
    } else {
        eprintln!("Hash did not match!");
        eprintln!(
            "  Expected: {}",
            base16::encode_lower(&params.expected_hash)
        );
        eprintln!(
            "    Actual: {}",
            base16::encode_lower(&hash_result.file_hash)
        );
        eprintln!("Your disk image may be corrupted!");
        exit(-1);
    }

    Ok(Some(hash_result))
}

fn find_hash(input: &PathBuf) -> Option<(HashAlg, &str, Vec<u8>)> {
    for (alg, hash_file) in HASH_FILES {
        let hash_filepath = input.parent()?.join(hash_file);
        if let Ok(file) = File::open(&hash_filepath) {
            if let Ok(Some(expected_hash)) =
                parse_hashfile(BufReader::new(file), input.file_name()?.to_str()?)
            {
                return Some((alg, hash_file, expected_hash));
            }
        }
    }

    None
}

fn parse_hashfile(hash_file: impl BufRead, input_file: &str) -> anyhow::Result<Option<Vec<u8>>> {
    for line in hash_file.lines() {
        match line?.split_once(char::is_whitespace) {
            Some((hash, file)) if file.trim_start() == input_file => {
                match base16::decode(hash.as_bytes()) {
                    Ok(decoded) => return Ok(Some(decoded)),
                    Err(err) => {
                        eprintln!("Failed to decode hash");
                        return Err(err.into());
                    }
                }
            }
            None => return Err(anyhow!("Invalid hash file")),
            _ => continue,
        }
    }

    Ok(None)
}

#[tracing::instrument]
fn ask_hash_loop(cf: CompressionFormat) -> anyhow::Result<Option<BeginHashParams>> {
    loop {
        match ask_hash_once(cf) {
            Ok(bhp) => {
                return Ok(Some(bhp));
            }
            Err(e) => match e.downcast::<Recoverable>()? {
                Recoverable::AskAgain => {
                    continue;
                }
                Recoverable::Skip => {
                    return Ok(None);
                }
            },
        }
    }
}

#[tracing::instrument]
fn ask_hash_once(cf: CompressionFormat) -> anyhow::Result<BeginHashParams> {
    let input_hash = Text::new("What is the file's hash?")
        .with_help_message(
            "We will guess the hash algorithm from your input. Press ESC or type \"skip\" to skip.",
        )
        .prompt_skippable()?;

    let (algs, hash) = match input_hash.as_deref() {
        None | Some("skip") => Err(Recoverable::Skip)?,
        Some(hash) => match parse_hash_input(hash) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("{e}");
                Err(Recoverable::AskAgain)?
            }
        },
    };

    let alg = match &algs[..] {
        &[] => {
            eprintln!("Could not detect the hash algorithm from your hash!");
            Err(Recoverable::AskAgain)?
        }
        &[only_alg] => {
            eprintln!("Detected {}", only_alg);
            only_alg
        }
        multiple => {
            let ans = Select::new("Which algorithm is it?", multiple.into()).prompt_skippable()?;
            if let Some(alg) = ans {
                alg
            } else {
                Err(Recoverable::AskAgain)?
            }
        }
    };

    let hasher_compression = ask_hasher_compression(cf, None)?;

    Ok(BeginHashParams {
        expected_hash: hash,
        alg,
        hasher_compression,
    })
}

#[tracing::instrument]
fn ask_hasher_compression(
    cf: CompressionFormat,
    hash_of: Option<HashOf>,
) -> anyhow::Result<CompressionFormat> {
    if cf.is_identity() {
        return Ok(cf);
    }

    let ans = hash_of.map(Ok).unwrap_or_else(|| {
        Select::new(
            "Is the hash calculated from the raw file or the compressed file?",
            vec![HashOf::Raw, HashOf::Compressed],
        )
        .prompt()
    })?;

    Ok(match ans {
        HashOf::Raw => cf,
        HashOf::Compressed => CompressionFormat::Identity,
    })
}

#[tracing::instrument(skip_all, fields(path))]
fn do_hashing(path: &Path, params: &BeginHashParams) -> anyhow::Result<FileHashInfo> {
    let mut file = File::open(path)?;

    // Calculate total file size
    let file_size = file.seek(std::io::SeekFrom::End(0))?;
    file.seek(std::io::SeekFrom::Start(0))?;

    let progress_bar = ProgressBar::new(file_size);
    progress_bar.set_style(
        ProgressStyle::with_template("{bytes:>10} / {total_bytes:<10} ({percent:^3}%) {wide_bar}")
            .unwrap(),
    );

    let decompress = decompress(params.hasher_compression, BufReader::new(file))
        .context("Failed to open input file with decompressor")?;

    let mut hashing = Hashing::new(
        params.alg,
        decompress,
        ByteSize::kib(512).as_u64() as usize, // TODO
    );
    loop {
        for _ in 0..32 {
            match hashing.next() {
                Some(_) => {}
                None => return Ok(hashing.finalize()?),
            }
        }
        progress_bar.set_position(hashing.get_reader_mut().get_mut().stream_position()?);
    }
}

#[derive(Debug)]
struct BeginHashParams {
    expected_hash: Vec<u8>,
    alg: HashAlg,
    hasher_compression: CompressionFormat,
}

/// A signaling error for the outer loop.
#[derive(Debug, thiserror::Error)]
#[error("Recoverable error")]
enum Recoverable {
    AskAgain,
    Skip,
}

#[cfg(test)]
mod tests {
    use super::parse_hashfile;
    use std::io::Cursor;

    #[test]
    fn parse_simple_hashfile() {
        let mut cursor = Cursor::new(
            "bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965  archlinux-2024.11.01-x86_64.iso"
        );

        assert_eq!(
            parse_hashfile(&mut cursor, "archlinux-2024.11.01-x86_64.iso").unwrap(),
            Some(
                base16::decode("bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965")
                    .unwrap()
            ),
        );
    }

    #[test]
    fn parse_complicated_hashfile() {
        let mut cursor = Cursor::new(
        "bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965  archlinux-2024.11.01-x86_64.iso\n\
        bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965  archlinux-x86_64.iso\n\
        c64745475da03a31f270b92e9abfbe7b6315596c7c97b17ef9a373433562a4a4  archlinux-bootstrap-2024.11.01-x86_64.tar.zst\n\
        c64745475da03a31f270b92e9abfbe7b6315596c7c97b17ef9a373433562a4a4  archlinux-bootstrap-x86_64.tar.zst",
        );

        for (filename, hash) in &[
            (
                "archlinux-2024.11.01-x86_64.iso",
                "bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965",
            ),
            (
                "archlinux-x86_64.iso",
                "bceb3dded8935c1d3521c475a69ae557e082839b46d921c8b400524470b5c965",
            ),
            (
                "archlinux-bootstrap-2024.11.01-x86_64.tar.zst",
                "c64745475da03a31f270b92e9abfbe7b6315596c7c97b17ef9a373433562a4a4",
            ),
            (
                "archlinux-bootstrap-x86_64.tar.zst",
                "c64745475da03a31f270b92e9abfbe7b6315596c7c97b17ef9a373433562a4a4",
            ),
        ] {
            assert_eq!(
                parse_hashfile(&mut cursor, filename).unwrap(),
                Some(base16::decode(hash).unwrap())
            );
        }
    }
}
