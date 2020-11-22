//! Program to get/set extended ACL's.
//!
//! To read an ACL from myfile and write it to stdout as JSON:
//!     exacl myfile
//!
//! To set the ACL for myfile from JSON passed via stdin (complete replacement):
//!     exacl --set myfile
//!
//! To get/set the ACL of a symlink itself, instead of the file it points to,
//! use the -h option.
//!
//! To get/set the default ACL (on Linux), use the -d option.

use exacl::{getfacl, setfacl, AclEntry, AclOption};
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "exacl", about = "Read or write a file's ACL.")]
struct Opt {
    /// Set file's ACL.
    #[structopt(long)]
    set: bool,

    /// Get or set the default ACL.
    #[structopt(short = "d", long)]
    default: bool,

    /// Get or set the ACL of a symlink itself.
    #[structopt(short = "h", long)]
    symlink: bool,

    /// Input files
    #[structopt(parse(from_os_str))]
    files: Vec<PathBuf>,
}

const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;

fn main() {
    env_logger::init();

    let opt = Opt::from_args();

    let mut options = AclOption::empty();
    if opt.default {
        options |= AclOption::DEFAULT_ACL;
    }
    if opt.symlink {
        options |= AclOption::SYMLINK_ACL;
    }

    let exit_code = if opt.set {
        set_acl(&opt.files, options)
    } else {
        get_acl(&opt.files, options)
    };

    process::exit(exit_code);
}

fn get_acl(paths: &[PathBuf], options: AclOption) -> i32 {
    for path in paths {
        if let Err(err) = dump_acl(path, options) {
            eprintln!("{}", err);
            return EXIT_FAILURE;
        }
    }

    EXIT_SUCCESS
}

fn set_acl(paths: &[PathBuf], options: AclOption) -> i32 {
    let reader = io::BufReader::new(io::stdin());
    let entries: Vec<AclEntry> = match serde_json::from_reader(reader) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("JSON parser error: {}", err);
            return EXIT_FAILURE;
        }
    };

    // FIXME(bfish): Preflight the entries here, not inside setfacl?
    // Should there be a new API: `checkfacl`?

    if let Err(err) = setfacl(paths, &entries, options) {
        eprintln!("{}", err);
        return EXIT_FAILURE;
    }

    EXIT_SUCCESS
}

fn dump_acl(path: &Path, options: AclOption) -> io::Result<()> {
    let entries = getfacl(path, options)?;
    serde_json::to_writer(io::stdout(), &entries)?;
    println!(); // add newline
    Ok(())
}
