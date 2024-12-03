#![allow(dead_code, unreachable_code, unused_variables)]
use anyhow::Result;
use aliyun_openapi_core_rust_sdk::client::rpc::RPClient;

#[derive(Debug, Clone)]
pub struct AliyunCFG {
    rpc_client: RPClient,
    region_id: String,
}


impl AliyunCFG {
    pub fn new(access_key: &str, access_secret: &str, region_id: &str) -> Self {
        Self {
            rpc_client: RPClient::new(access_key, access_secret, "https://ecs.aliyuncs.com/"),
            region_id: region_id.to_string(),
        }
    }

    pub async fn add_whitelist(&self, sg_id: &str, ip: &str) -> Result<()> {
        
        if ip == "127.0.0.1" {
            return Ok(());
        }
        todo!("Call aliyun api to add ip to whitelist");
        Ok(())
    }

    pub async fn del_whitelist(&self, sg_id: &str, ip: &str) -> Result<()> {
        todo!("Call aliyun api to del ip from whitelist")
    }

    pub async fn get_whitelist(&self, sg_id: &str) -> Result<String> {
        let response = &self.rpc_client.clone()
            .version("2014-05-26")
            .get("DescribeSecurityGroupAttribute")
            .query([("RegionId", self.region_id.as_str()), ("SecurityGroupId", sg_id)])
            .text()
            .await?;
        println!("{}", response);
        Ok(response.to_owned())
    }

    pub async fn modify_sg(&self, sg_id: &str, sg_name: &str) -> Result<()> {
        todo!("Call aliyun api to modify sg")
    }
}

