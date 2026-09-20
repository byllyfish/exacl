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
//!
//! You can also get/set extended ACL's using an open file descriptor using the
//! `--fd` option.

use exacl::{AclEntry, AclOption, getfacl, setfacl};
use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::path::PathBuf;
use std::process;

use clap::Parser;

#[derive(clap::Parser)]
#[command(name = "exacl", about = "Read or write a file's ACL.")]
#[allow(clippy::struct_excessive_bools)]
struct Opt {
    /// Set file's ACL from STDIN or `--acl` arguments.
    #[arg(long)]
    set: bool,

    /// Set ACL to specified value (repeat to combine multiple ACL's).
    /// If not provided, the ACL will be read from stdin.
    #[arg(long, requires = "set")]
    acl: Vec<String>,

    /// Get or set the access ACL.
    #[arg(short = 'a', long)]
    access: bool,

    /// Get or set the default ACL.
    #[arg(short = 'd', long)]
    default: bool,

    /// Get or set the ACL of a symlink itself.
    #[arg(short = 's', long)]
    symlink: bool,

    /// Get ACL as native ID only.
    #[arg(short = 'n', long)]
    native: bool,

    /// Format of input or output.
    #[arg(value_enum, short = 'f', long, default_value = "json")]
    format: Format,

    /// Input file descriptor to use instead of <FILES>.
    #[arg(long, group = "input")]
    fd: Option<RawFd>,

    /// Input files.
    #[arg(num_args = 1.., group = "input", required=true)]
    files: Vec<PathBuf>,
}

impl Opt {
    /// Retrieve `AclOption` flags from command line options.
    fn options(&self) -> AclOption {
        let mut options = AclOption::empty();
        options.set(AclOption::ACCESS_ACL, self.access);
        options.set(AclOption::DEFAULT_ACL, self.default);
        options.set(AclOption::SYMLINK_ACL, self.symlink);
        options.set(AclOption::NATIVE_ID, self.native);
        options
    }
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

    let exit_code = match (opt.set, opt.fd) {
        (false, None) => get_acl(&opt.files, opt.options(), opt.format),
        (false, Some(fd)) => get_acl_fd(fd, opt.options(), opt.format),
        (true, None) => set_acl(&opt.files, opt.options(), opt.format, &opt.acl),
        (true, Some(fd)) => set_acl_fd(fd, opt.options(), opt.format, &opt.acl),
    };

    process::exit(exit_code);
}

fn get_acl(paths: &[PathBuf], options: AclOption, format: Format) -> i32 {
    for path in paths {
        if let Err(err) = getfacl(path, options).and_then(|entries| write_acl(&entries, format)) {
            eprintln!("{err}");
            return EXIT_FAILURE;
        }
    }

    EXIT_SUCCESS
}

fn get_acl_fd(fd: RawFd, options: AclOption, format: Format) -> i32 {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };

    if let Err(err) = getfacl(fd, options).and_then(|entries| write_acl(&entries, format)) {
        eprintln!("{err}");
        return EXIT_FAILURE;
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

fn set_acl_fd(fd: RawFd, options: AclOption, format: Format, acls: &[String]) -> i32 {
    let Some(entries) = read_acl_input(format, acls) else {
        return EXIT_FAILURE;
    };

    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    if let Err(err) = setfacl(fd, &entries, options) {
        eprintln!("{err}");
        return EXIT_FAILURE;
    }

    EXIT_SUCCESS
}

fn write_acl(entries: &[AclEntry], format: Format) -> io::Result<()> {
    match format {
        #[cfg(feature = "serde")]
        Format::Json => {
            serde_json::to_writer(io::stdout(), &entries)?;
            println!(); // add newline
            Ok(())
        }
        #[cfg(not(feature = "serde"))]
        Format::Json => {
            panic!("serde not supported");
        }
        Format::Std => exacl::to_writer(io::stdout(), entries),
    }
}

fn read_acl_input(format: Format, acls: &[String]) -> Option<Vec<AclEntry>> {
    if acls.is_empty() {
        // Read one ACL from stdin.
        read_input(io::stdin(), format)
    } else {
        // Read multiple ACLs and combine them.
        let mut entries = vec![];
        for acl in acls {
            let ents = read_input(acl.as_bytes(), format)?;
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
