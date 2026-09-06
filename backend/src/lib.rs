// The binary is a thin wrapper around this: everything worth testing lives in
// the modules, and integration tests reach them through here.

pub mod api;
pub mod cache;
pub mod policy;
pub mod session;
pub mod store;
