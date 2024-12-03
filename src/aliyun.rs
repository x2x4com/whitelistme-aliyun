#![allow(dead_code, unreachable_code, unused_variables, unused_imports)]
use anyhow::Result;


#[derive(Debug)]
pub struct AliyunCFG {
    access_key: String,
    access_secret: String,
    region_id: String,
}

impl AliyunCFG {
    pub fn new(access_key: &str, access_secret: &str, region_id: &str) -> Self {
        Self {
            access_key: access_key.to_string(),
            access_secret: access_secret.to_string(),
            region_id: region_id.to_string(),
        }
    }
    pub async fn add_whitelist(&self, sg_id: &str, ip: &str) -> Result<()> {
        
        println!("{} {} {} {} {ip:?}", self.access_key, self.access_secret, self.region_id, sg_id);
        if ip == "127.0.0.1" {
            return Ok(());
        }
        todo!("Call aliyun api to add ip to whitelist");
        Ok(())
    }

    pub async fn del_whitelist(&self, sg_id: &str, ip: &str) -> Result<()> {
        todo!("Call aliyun api to del ip from whitelist")
    }

    pub async fn get_whitelist(&self, sg_id: &str) -> Result<()> {
        todo!("Call aliyun api to get whitelist")
    }

    pub async fn modify_sg(&self, sg_id: &str, sg_name: &str) -> Result<()> {
        todo!("Call aliyun api to modify sg")
    }
}

