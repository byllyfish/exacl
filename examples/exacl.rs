//! Program to get/set extended ACL's.
//!
//! To read an ACL from myfile and write it to stdout as JSON:
//!     exacl myfile
//!
//! To set the ACL for myfile from JSON passed via stdin (complete replacement):
//!     exacl --set myfile
//!
//! To set the ACL for myfile from JSON passed via command-line argument:
//!     exacl --set --acl "[...]" myfile
//!
//! To get/set the ACL of a symlink itself, instead of the file it points to,
//! use the -s option.
//!
//! To get/set the default ACL (on Linux), use the -d option.
//!
//! To get the ACL without translating uid/gid's to names, use the -n option.
//!
//! To use the delimited text format instead of JSON, use the `-f std` option.

use exacl::{AclEntry, AclOption, getfacl, setfacl};
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

#[derive(clap::Parser)]
#[command(name = "exacl", about = "Read or write a file's ACL.")]
#[allow(clippy::struct_excessive_bools)]
struct Opt {
    /// Set file's ACL from STDIN or `--acl` arguments.
    #[arg(long)]
    set: bool,

    /// Get or set the access ACL.
    #[arg(short = 'a', long)]
    access: bool,

    /// Get or set the default ACL.
    #[arg(short = 'd', long)]
    default: bool,

    /// Get or set the ACL of a symlink itself.
    #[arg(short = 's', long)]
    symlink: bool,

    /// Get ACL as numeric only.
    #[arg(short = 'n', long)]
    numeric: bool,

    /// Set ACL to specified value (may combine multiple ACL's).
    #[arg(long)]
    acl: Vec<String>,

    /// Format of input or output.
    #[arg(value_enum, short = 'f', long, default_value = "json")]
    format: Format,

    /// Input files
    #[arg()]
    files: Vec<PathBuf>,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
#[value(rename_all = "lower")]
enum Format {
    Json,
    Std,
}

const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;

fn main() {
    env_logger::init();

    let opt = Opt::parse();

    let mut options = AclOption::empty();
    if opt.access {
        options |= AclOption::ACCESS_ACL;
    }
    if opt.default {
        options |= AclOption::DEFAULT_ACL;
    }
    if opt.symlink {
        options |= AclOption::SYMLINK_ACL;
    }
    if opt.numeric {
        options |= AclOption::NUMERIC_ACL;
    }

    let exit_code = if opt.set {
        set_acl(&opt.files, options, opt.format, &opt.acl)
    } else if !opt.acl.is_empty() {
        eprintln!("Use of --acl requires --set");
        EXIT_FAILURE
    } else {
        get_acl(&opt.files, options, opt.format)
    };

    process::exit(exit_code);
}

fn get_acl(paths: &[PathBuf], options: AclOption, format: Format) -> i32 {
    for path in paths {
        if let Err(err) = dump_acl(path, options, format) {
            eprintln!("{err}");
            return EXIT_FAILURE;
        }
    }

    EXIT_SUCCESS
}

fn set_acl(paths: &[PathBuf], options: AclOption, format: Format, acls: &[String]) -> i32 {
    let Some(entries) = read_acl_input(format, acls) else {
        return EXIT_FAILURE;
    };

    if let Err(err) = setfacl(paths, &entries, options) {
        eprintln!("{err}");
        return EXIT_FAILURE;
    }

    EXIT_SUCCESS
}

fn dump_acl(path: &Path, options: AclOption, format: Format) -> io::Result<()> {
    let entries = getfacl(path, options)?;

    match format {
        #[cfg(feature = "serde")]
        Format::Json => {
            serde_json::to_writer(io::stdout(), &entries)?;
            println!(); // add newline
        }
        #[cfg(not(feature = "serde"))]
        Format::Json => {
            panic!("serde not supported");
        }
        Format::Std => exacl::to_writer(io::stdout(), &entries)?,
    }

    Ok(())
}

fn read_acl_input(format: Format, acls: &[String]) -> Option<Vec<AclEntry>> {
    if acls.is_empty() {
        // Read one ACL from stdin.
        let Some(entries) = read_input(io::stdin(), format) else {
            return None;
        };
        Some(entries)
    } else {
        // Read multiple ACLs and combine them.
        let mut entries = vec![];
        for acl in acls {
            let Some(ents) = read_input(acl.as_bytes(), format) else {
                return None;
            };
            entries.extend_from_slice(&ents);
        }
        Some(entries)
    }
}

fn read_input<R>(source: R, format: Format) -> Option<Vec<AclEntry>>
where
    R: io::Read,
{
    let reader = io::BufReader::new(source);

    let entries: Vec<AclEntry> = match format {
        // Read JSON format.
        #[cfg(feature = "serde")]
        Format::Json => match serde_json::from_reader(reader) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("JSON parser error: {err}");
                return None;
            }
        },
        #[cfg(not(feature = "serde"))]
        Format::Json => {
            panic!("serde not supported");
        }
        // Read Std format.
        Format::Std => match exacl::from_reader(reader) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("Std parser error: {err}");
                return None;
            }
        },
    };

    Some(entries)
}
