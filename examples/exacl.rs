//! Program to get/set extended ACL's.
//!
//! To read an ACL from myfile and write it to stdout as JSON:
//!     exacl myfile
//!
//! To set the ACL for myfile from JSON passed via stdin (complete replacement):
//!     exacl --set myfile
//!
//! To get/set the ACL of a symlink itself, instead of the file it points to,
//! use the -s option.
//!
//! To get/set the default ACL (on Linux), use the -d option.

use exacl::{getfacl, setfacl, AclEntry, AclOption};
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

#[derive(clap::Parser)]
#[command(name = "exacl", about = "Read or write a file's ACL.")]
#[allow(clippy::struct_excessive_bools)]
struct Opt {
    /// Set file's ACL.
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

    let exit_code = if opt.set {
        set_acl(&opt.files, options, opt.format)
    } else {
        get_acl(&opt.files, options, opt.format)
    };

    process::exit(exit_code);
}

fn get_acl(paths: &[PathBuf], options: AclOption, format: Format) -> i32 {
    for path in paths {
        if let Err(err) = dump_acl(path, options, format) {
            eprintln!("{}", err);
            return EXIT_FAILURE;
        }
    }

    EXIT_SUCCESS
}

fn set_acl(paths: &[PathBuf], options: AclOption, format: Format) -> i32 {
    let entries = match read_input(format) {
        Some(entries) => entries,
        None => return EXIT_FAILURE,
    };

    if let Err(err) = setfacl(paths, &entries, options) {
        eprintln!("{}", err);
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
    };

    Ok(())
}

fn read_input(format: Format) -> Option<Vec<AclEntry>> {
    let reader = io::BufReader::new(io::stdin());

    let entries: Vec<AclEntry> = match format {
        // Read JSON format.
        #[cfg(feature = "serde")]
        Format::Json => match serde_json::from_reader(reader) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("JSON parser error: {}", err);
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
                eprintln!("Std parser error: {}", err);
                return None;
            }
        },
    };

    Some(entries)
}
