use axum::{
    extract::State,
    response::Html, 
    routing::get, 
    Json, 
    Router,
    http::StatusCode,
};
use tower_http::{
    // services::ServeDir,
    trace::TraceLayer
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde::Deserialize;
use std::env;
use anyhow::Result;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use hex::ToHex;
use axum_client_ip::{InsecureClientIp, SecureClientIp, SecureClientIpSource};
use std::net::SocketAddr;

mod js;

#[derive(Deserialize, Debug)]
struct WhitelistMeJson {
    name: String,
    auth: String,
    ts: String
}

#[derive(Clone, Debug)]
struct AppState {
    allow_user_list: AllowUserList,
    aliyun_access_key: String,
    aliyun_access_secret: String,
    aliyun_region_id: String,
    aliyun_vpc_sg_id: String,
}

type AllowUserList = HashMap<String, String>;

async fn white_list_me_form() -> Html<String> {
    Html(
        format!(r#"
        <!doctype html>
        <html>
            <head>
                <script>{}</script>
            </head>
            <body>
                <div id="form_body">
                    <form action="/whitelistme" method="post" id="whitelistme">
                        <label for="name">
                            Name:
                            <input type="text" name="name" id="name">
                        </label>

                        <label>
                            Password:
                            <input type="password" name="password" id="password">
                        </label>

                        <button type="submit">Submit</button>
                    </form>
                </div>
            </body>
            <script>{}</script>
        </html>
        "#, js::CRYPTO_JS, js::SUBMIT)
    )
}

async fn white_list_me(
    _insecure_ip: InsecureClientIp, 
    secure_ip: SecureClientIp,
    State(state): State<AppState>, 
    Json(input): Json<WhitelistMeJson>,
) -> (StatusCode, String) {
    // println!("{:?}, {}, {}, {}", state.allow_user_list, state.aliyun_access_key, state.aliyun_access_secret, state.aliyun_region_id);
    // println!("Hello, {}! {}, {}", input.name, input.auth, input.ts);
    // try get user from allowed list key
    let allowed_user = state.allow_user_list.get(&input.name);
    if allowed_user.is_none() {
        return (StatusCode::FORBIDDEN, "not allowed".to_string());
    }
    let tmp_arr = format!("{}{}{}", &input.name, allowed_user.unwrap(), &input.ts);
    let mut hasher = Sha1::new();
    hasher.update(tmp_arr.as_bytes());
    let tmp_str_hashed = hasher.finalize();
    // println!("{:?}", String::from_utf8_lossy(&tmp_str_hashed));
    let hex_str = tmp_str_hashed.as_slice().encode_hex::<String>();
    // println!("hashed: {}", &hex_str);
    if hex_str != input.auth {
        return (StatusCode::FORBIDDEN, "not allowed".to_string());
    }
    // get user ip
    //println!("{insecure_ip:?} {secure_ip:?}");
    let is_success_add = add_whitelist(
        &state.aliyun_access_key, 
        &state.aliyun_access_secret, 
        &state.aliyun_region_id,
        &state.aliyun_vpc_sg_id,
        &secure_ip.0.to_string()
    ).await;
    if is_success_add.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string());
    }
    (StatusCode::OK, "OK".to_string())
}

async fn add_whitelist(access_key: &str, access_secret: &str, region_id: &str, sg_id: &str, ip: &str) -> Result<()> {
    println!("{access_key:?} {access_secret:?} {region_id:?} {sg_id:?} {ip:?}");
    if ip == "127.0.0.1" {
        return Ok(());
    }
    todo!("Call aliyun api to add ip to whitelist");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()>{
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "tower_http=info,middleware=info");
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap(),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    let ip = env::var("IP").unwrap_or("127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or("3000".to_string());
    let listen = format!("{}:{}", ip, port);
    let aliyun_access_key = env::var("ALIYUN_ACCESS_KEY").expect("ALIYUN_ACCESS_KEY is not set");
    let aliyun_access_secret = env::var("ALIYUN_ACCESS_SECRET").expect("ALIYUN_ACCESS_SECRET is not set");
    let aliyun_vpc_sg_id = env::var("ALIYUN_VPC_SG_ID").expect("ALIYUN_VPC_SG_ID is not set");
    let aliyun_region_id = env::var("ALIYUN_REGION_ID").unwrap_or("cn-zhangjiakou".to_string());
    let allow_user_pass = env::var("ALLOW_USER_PASS").unwrap_or("{}".to_string());
    
    let allow_user_list: AllowUserList = serde_json::from_str(&allow_user_pass)?;

    let state = AppState {
        allow_user_list,
        aliyun_access_key,
        aliyun_access_secret,
        aliyun_region_id,
        aliyun_vpc_sg_id,
    };

    println!("Listening on http://{}", listen.as_str());
    // build our application with a single route
    let app = Router::new()
        .route("/whitelistme", get(white_list_me_form).post(white_list_me))
        //.nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(SecureClientIpSource::ConnectInfo.into_extension())
        .layer(TraceLayer::new_for_http());

    // run our app with hyper, listening globally on port 3000
    // let addr = SocketAddr::from_str(listen.as_str()).unwrap();
    let listener = tokio::net::TcpListener::bind(listen.as_str()).await.unwrap();
    axum::serve(
        listener, 
        app.into_make_service_with_connect_info::<SocketAddr>()
    )
    .await
    .unwrap();
    Ok(())
}
