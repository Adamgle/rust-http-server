use std::path::PathBuf;

use tokio::sync::MutexGuard;

use crate::{config::Config, routes::RouteHandlerContext};

/// Paths could be declared as a piece of a path that a path from request starts with.
/// They have to be relative and contain no leading slashes, strictly UNIX
/// based approach to absolute paths handling.
// const PATHS: &[PathBuf] = &[PathBuf::from("asd")];

struct Middleware {
    paths: Vec<PathBuf>,
}

impl Middleware {
    pub fn next(&self, config: MutexGuard<'_, Config>, ctx: RouteHandlerContext) -> String {
        todo!()
    }
}
