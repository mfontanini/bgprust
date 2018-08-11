extern crate chrono;
extern crate ipnetwork;
extern crate byteorder;
#[macro_use] extern crate enum_primitive_derive;
extern crate num_traits;

pub mod models;
pub mod parser;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
