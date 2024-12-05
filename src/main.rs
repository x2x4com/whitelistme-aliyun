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
use std::{env, thread};
use anyhow::Result;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use hex::ToHex;
use axum_client_ip::{InsecureClientIp, SecureClientIp, SecureClientIpSource};
use std::net::SocketAddr;
use std::time::{UNIX_EPOCH, SystemTime};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::time::*;

mod js;
mod aliyun;

#[derive(Deserialize, Debug)]
struct WhitelistMeJson {
    name: String,
    auth: String,
    ts: u64
}

#[derive(Clone, Debug)]
struct AppState {
    allow_user_list: AllowUserList,
    aliyun_access_key: String,
    aliyun_access_secret: String,
    aliyun_region_id: String,
    aliyun_vpc_sg_id: String,
    allow_time_diff: u64,
    allow_port_range: Vec<String>,
    allow_valid_time_duration: u64,
    allow_cleanup_task_interval: u64,
}

type AllowUserList = HashMap<String, String>;

async fn white_list_me_form() -> Html<String> {
    Html(
        format!(r#"
        <!doctype html>
        <html>
            <head>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>
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
        "#, js::SUBMIT)
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
        return (StatusCode::UNAUTHORIZED, "Not allowed".to_string());
    }
    // check timestamp is valid, allow +-allow_time_diff seconds
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if now > input.ts + state.allow_time_diff || now < input.ts - state.allow_time_diff {
        return (StatusCode::UNAUTHORIZED, "Timestamp is not valid".to_string());
    }
    let tmp_arr = format!("{}{}{}", &input.name, allowed_user.unwrap(), &input.ts);
    let mut hasher = Sha1::new();
    hasher.update(tmp_arr.as_bytes());
    let tmp_str_hashed = hasher.finalize();
    // println!("{:?}", String::from_utf8_lossy(&tmp_str_hashed));
    let hex_str = tmp_str_hashed.as_slice().encode_hex::<String>();
    // println!("hashed: {}", &hex_str);
    if hex_str != input.auth {
        return (StatusCode::UNAUTHORIZED, "Not allowed".to_string());
    }
    // get user ip
    //println!("{insecure_ip:?} {secure_ip:?}");
    let aly = aliyun::AliyunCFG::new(
        &state.aliyun_access_key, 
        &state.aliyun_access_secret, 
        &state.aliyun_region_id
    );
    let duration = chrono::Duration::seconds(state.allow_valid_time_duration as i64);
    let is_success_add = aly.add_whitelist(&state.aliyun_vpc_sg_id, &secure_ip.0.to_string(), state.allow_port_range, duration).await;
    if is_success_add.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, is_success_add.err().unwrap().to_string());
    }
    (StatusCode::OK, is_success_add.unwrap())
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
    let allow_time_diff = env::var("ALLOW_TIME_DIFF").unwrap_or("300".to_string()).parse::<u64>().unwrap();
    // let allow_ports: Vec<u16> = env::var("ALLOW_PORTS").unwrap_or("22".to_string()).split(",").into_iter().map(|s| s.parse::<u16>().unwrap()).collect();
    // todo 要考虑一下 IpProtocol, 应该改成TCP:PORT/PORT
    let allow_port_range: Vec<String> = env::var("ALLOW_PORT_RANGE").unwrap_or("TCP:22/22".to_string()).split(",").into_iter().map(|s| s.to_string()).collect();
    let allow_valid_time_duration = env::var("ALLOW_VALID_TIME_DURATION").unwrap_or("86400".to_string()).parse::<u64>().unwrap();
    let allow_cleanup_task_interval = env::var("ALLOW_CLEANUP_TASK_INTERVAL").unwrap_or("3600".to_string()).parse::<u64>().unwrap();
    
    let allow_user_list: AllowUserList = serde_json::from_str(&allow_user_pass)?;

    // for port in allow_ports {
    //     let t = format!("{}/{}", port, port);
    //     // check "port/port" in allow_port_range then add it to allow_port_range
    //     if !allow_port_range.contains(&t) {
    //         allow_port_range.push(t);
    //     }
    // }

    let state = AppState {
        allow_user_list,
        aliyun_access_key,
        aliyun_access_secret,
        aliyun_region_id,
        aliyun_vpc_sg_id,
        allow_time_diff,
        allow_port_range,
        allow_valid_time_duration,
        allow_cleanup_task_interval
    };

    let state_arc = Arc::new(state.clone());

    let _ = thread::spawn(move || {
        println!("Starting whitelistme cleanup task...");
        let state = state_arc.clone();
        let rt = Runtime::new().unwrap();
        let aly = aliyun::AliyunCFG::new(
            &state.aliyun_access_key, 
            &state.aliyun_access_secret, 
            &state.aliyun_region_id
        );
        rt.block_on(async move {
            loop {
                // println!("Cleanup task started...");
                let result = aly.get_whitelist(&state.aliyun_vpc_sg_id).await;
                if let Ok(whitelist) = result {
                    let permissions = whitelist.permissions.permission;
                    for permission in permissions {
                        if permission.is_expired() {
                            println!("Permission expired: {:?}", &permission.security_group_rule_id);
                            let _ = aly.clean_whitelist(&state.aliyun_vpc_sg_id, &permission.security_group_rule_id).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(state.allow_cleanup_task_interval)).await;
            }
        });
    });


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
