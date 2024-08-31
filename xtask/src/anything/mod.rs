extern crate alloc;

use {
    alloc::{boxed::Box, format, string::String},
    core::{
        any::Any,
        fmt::{Debug, Display, Formatter},
        panic::Location,
    },
};

pub mod nothing;

pub type Result<T> = core::result::Result<T, Anything>;
pub type Exception<T> = core::result::Result<T, Anything>;

pub auto trait NotAnything {}
impl !NotAnything for Anything {}
impl<T> NotAnything for Box<T> {}

pub struct Anything {
    error: Box<dyn DynError>,

    #[cfg(debug_assertions)]
    origin: &'static Location<'static>,
}

impl Anything {
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn new<T: DynError + 'static>(error: T) -> Anything {
        Anything {
            error: Box::new(error),
            #[cfg(debug_assertions)]
            origin: Location::caller(),
        }
    }

    #[cfg_attr(debug_assertions, track_caller)]
    pub fn new_error<T: DynError + 'static>(error: T) -> Result<()> {
        Err(Anything {
            error: Box::new(error),
            #[cfg(debug_assertions)]
            origin: Location::caller(),
        })
    }

    #[cfg_attr(debug_assertions, track_caller)]
    pub fn assert<T: DynError + 'static>(error_if_false: bool, error: T) -> Result<()> {
        if error_if_false {
            return Ok(());
        }
        Err(Anything {
            error: Box::new(error),
            #[cfg(debug_assertions)]
            origin: Location::caller(),
        })
    }

    pub fn get_error(&self) -> &dyn Any {
        self.error.as_any()
    }

    pub fn get_origin(&self) -> Option<Location<'static>> {
        #[cfg(debug_assertions)]
        return Some(self.origin.clone());
        #[cfg(not(debug_assertions))]
        return None;
    }
}

impl Display for Anything {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        let v = write!(f, "[{}:{}:{}] {:?}", self.origin.file(), self.origin.line(), self.origin.column(), self.error.format());
        #[cfg(not(debug_assertions))]
        let v = write!(f, "{:?}", self.error.format());
        v
    }
}

impl Debug for Anything {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        let v = write!(f, "'{:?}'\n    at {}:{}:{}", self.error.format(), self.origin.file(), self.origin.line(), self.origin.column());
        #[cfg(not(debug_assertions))]
        let v = write!(f, "{:?}", self.error.format());
        v
    }
}

impl<T: DynError + 'static> From<T> for Anything {
    #[cfg_attr(debug_assertions, track_caller)]
    fn from(value: T) -> Self {
        Anything {
            error: Box::new(value),
            #[cfg(debug_assertions)]
            origin: Location::caller(),
        }
    }
}

pub trait DynError {
    fn as_any(&self) -> &dyn Any;
    fn format(&self) -> String;
}

impl<T: Any + NotAnything + Debug> DynError for T {
    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }

    fn format(&self) -> String {
        format!("{:?}", self)
    }
}
