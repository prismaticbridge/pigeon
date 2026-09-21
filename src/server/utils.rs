use arrayvec::ArrayString;
use pigeon::{GetKeyRequest, constants::GETKEY_URL};

///Print when compiled in debug mode, do nothing otherwise
// this might be better than the client one? idk macro rules are annoying, im not changing it
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        if !cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}

///Render free get killed after 15 minutes with no activity, so make render ping itself every 14 minutes so it never dies
pub async fn ping_thread() {
    let client = reqwest::Client::new();

    //make a random query
    let request = GetKeyRequest {
        target: ArrayString::from("gwiggly").unwrap(),
    };
    let payload = postcard::to_allocvec(&request).unwrap();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_mins(14)).await;
        let _result = client.get(&*GETKEY_URL).body(payload.clone()).send().await;
    }
}
