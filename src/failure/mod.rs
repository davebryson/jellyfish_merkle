

pub use failure::{
    _core, bail, ensure, err_msg, format_err, AsFail, Backtrace, Causes, Compat, Context, Error,
    Fail, ResultExt, SyncFailure,
};

/// Prelude module containing most commonly used types/macros this crate exports.
pub mod prelude {
    pub use failure::{bail, ensure, err_msg, format_err, Error, Fail, ResultExt};
}