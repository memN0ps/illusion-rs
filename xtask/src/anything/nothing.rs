extern crate alloc;

pub auto trait NotNothing {}
impl !NotNothing for Nothing {}
impl<T> NotNothing for Box<T> {}

#[derive(Debug)]
pub struct Nothing;

impl<T: NotNothing> From<T> for Nothing {
    fn from(_: T) -> Self {
        Nothing
    }
}
