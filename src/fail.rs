//! Error handling convenience functions.

use log::debug;
use std::fmt;
use std::io;

/// Log a message and return an `io::Error` with the value of errno.
pub fn log_err<R, T>(ret: R, func: &str, arg: T) -> io::Error
where
    R: fmt::Display,
    T: fmt::Debug,
{
    let err = io::Error::last_os_error();
    debug!("{}({:?}) returned {}, err={}", func, arg, ret, err);
    err
}

/// Log a message and return an `io::Error` for a given error code.
pub fn log_from_err<T>(ret: i32, func: &str, arg: T) -> io::Error
where
    T: fmt::Debug,
{
    assert!(ret > 0);
    let err = io::Error::from_raw_os_error(ret);
    debug!("{}({:?}) returned {}, err={}", func, arg, ret, err);
    err
}

/// Log a message and return an `io::Result` with the value of errno.
pub fn fail_err<R, T, U>(ret: R, func: &str, arg: T) -> io::Result<U>
where
    R: fmt::Display,
    T: fmt::Debug,
{
    Err(log_err(ret, func, arg))
}

/// Log a message and return an `io::Result` for a given error code.
pub fn fail_from_err<T, U>(ret: i32, func: &str, arg: T) -> io::Result<U>
where
    T: fmt::Debug,
{
    Err(log_from_err(ret, func, arg))
}

/// Return a custom `io::Result` with the given message.
pub(crate) fn fail_custom<U>(msg: &str) -> io::Result<U> {
    Err(io::Error::new(io::ErrorKind::Other, msg))
}
