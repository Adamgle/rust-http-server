use rust_http_server::config::Config;
use rust_http_server::tcp_handlers::run_tcp_server;
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = env::args().collect::<Vec<String>>();
    let config = Config::new(args).await?;

    if let Err(e) = run_tcp_server(config).await {
        eprintln!("Server crash: {}", e);
        return Err(e);
    }

    Ok(())
}
// struct MyStruct<'a> {
//     data: &'a mut i32,
// }

// fn _main() {
//     let mut value = 10;
//     let mut s = MyStruct { data: &mut value };

//     let s_ref: &MyStruct = &s; // immutable borrow of the struct

//     *s_ref.data += 1; // ✅ allowed: we're mutating the i32 via &mut i32
//     println!("{}", s_ref.data); // prints 11
// }
