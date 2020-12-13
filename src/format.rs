//! Implements helper functions for the built-in `AclEntry` format.

use serde::{ser, Serialize};
use std::fmt;

/// Write value of a simple enum as a `serde` serialized string.
pub fn write<'a, 'b, T: Serialize>(f: &'a mut fmt::Formatter<'b>, value: &T) -> fmt::Result {
    let mut serializer = EnumSerializer(f);
    value
        .serialize(&mut serializer)
        .expect("can't serialize value");
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum Error {
    Message(String),
    NotImplemented,
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::NotImplemented => write!(f, "Not implemented"),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

struct EnumSerializer<'a, 'b>(&'a mut fmt::Formatter<'b>);

const fn not_implemented<T>() -> Result<T> {
    Err(Error::NotImplemented)
}

impl<'a, 'b> ser::Serializer for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // Serialize a simple enum.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.0.write_str(variant).expect("can't format enum");
        Ok(())
    }

    fn serialize_bool(self, _v: bool) -> Result<()> {
        not_implemented()
    }

    fn serialize_i8(self, _v: i8) -> Result<()> {
        not_implemented()
    }

    fn serialize_i16(self, _v: i16) -> Result<()> {
        not_implemented()
    }

    fn serialize_i32(self, _v: i32) -> Result<()> {
        not_implemented()
    }

    fn serialize_i64(self, _v: i64) -> Result<()> {
        not_implemented()
    }

    fn serialize_u8(self, _v: u8) -> Result<()> {
        not_implemented()
    }

    fn serialize_u16(self, _v: u16) -> Result<()> {
        not_implemented()
    }

    fn serialize_u32(self, _v: u32) -> Result<()> {
        not_implemented()
    }

    fn serialize_u64(self, _v: u64) -> Result<()> {
        not_implemented()
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        not_implemented()
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        not_implemented()
    }

    fn serialize_char(self, _v: char) -> Result<()> {
        not_implemented()
    }

    fn serialize_str(self, _v: &str) -> Result<()> {
        not_implemented()
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        not_implemented()
    }

    fn serialize_none(self) -> Result<()> {
        not_implemented()
    }

    fn serialize_some<T>(self, _v: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn serialize_unit(self) -> Result<()> {
        not_implemented()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        not_implemented()
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        not_implemented()
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        not_implemented()
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        not_implemented()
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        not_implemented()
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        not_implemented()
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        not_implemented()
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeSeq for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeTuple for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeTupleStruct for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeTupleVariant for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeMap for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeStruct for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

impl<'a, 'b> ser::SerializeStructVariant for &mut EnumSerializer<'a, 'b> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        not_implemented()
    }

    fn end(self) -> Result<()> {
        not_implemented()
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn test_enum() {
        #[derive(Serialize)]
        enum E {
            Unit,
        }

        impl fmt::Display for E {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write(f, self)
            }
        }

        let u = E::Unit;
        let expected = "Unit";
        assert_eq!(format!("{}", u), expected);
    }
}
