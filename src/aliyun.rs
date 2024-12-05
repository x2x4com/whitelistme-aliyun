#![allow(dead_code, unreachable_code, unused_variables, unused_assignments)]
use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use aliyun_openapi_core_rust_sdk::client::rpc::RPClient;
use std::net::IpAddr;
use std::str::FromStr;
// use tokio::time::{sleep, Duration as TokioDuration};


#[derive(Debug, Clone)]
pub struct AliyunCFG {
    rpc_client: RPClient,
    region_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestAuthorizeSecurityGroup {
    pub region_id: String,
    pub security_group_id: String,
    pub permissions: Vec<SecurityGroupPermission>
}

impl RequestAuthorizeSecurityGroup {

    pub fn new(region_id: &str, security_group_id: &str, permissions: Vec<SecurityGroupPermission>) -> Self {
        Self {
            region_id: region_id.to_string(),
            security_group_id: security_group_id.to_string(),
            permissions
        }
    }

    pub fn to_vec(&self) -> Vec<(String, String)> {
        let mut v = vec![];
        v.push(("RegionId".to_string(), self.region_id.to_string()));
        v.push(("SecurityGroupId".to_string(), self.security_group_id.to_string()));
        for (i,p) in self.permissions.iter().enumerate() {
            // 注意阿里云不允许0开头
            let n = i + 1;
            let k = format!("Permissions.{}.SourceCidrIp", n);
            v.push((k, p.source_cidr_ip.to_string()));
            let k = format!("Permissions.{}.IpProtocol", n);
            v.push((k, p.ip_protocol.to_string()));
            let k = format!("Permissions.{}.PortRange", n);
            v.push((k, p.port_range.to_string()));
            let k = format!("Permissions.{}.Policy", n);
            v.push((k, p.policy.to_string()));
            let k = format!("Permissions.{}.Description", n);
            v.push((k, p.description.to_string()));
            let k = format!("Permissions.{}.Priority", n);
            v.push((k, p.priority.to_string()));
        }
        v
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestModifySecurityGroupRule {
    pub region_id: String,
    pub security_group_id: String,
    pub security_group_rule_id: String,
    pub policy: String,
    pub description: String,
    pub priority: i32,
    pub ipv6_source_cidr_ip: String,
    pub port_range: String,
    pub source_cidr_ip: String,
    pub ip_protocol: String,
}

impl RequestModifySecurityGroupRule {
    pub fn new (region_id: &str, security_group_id: &str, security_group_rule_id: &str, policy: &str, description: &str, ip: &str, port_range: &str, ip_protocol: &str, priority: i32) -> Self {
        // check ip is ipv4 or ipv6
        if IpAddr::from_str(&ip).unwrap().is_ipv4() {
            Self {
                region_id: region_id.to_string(),
                security_group_id: security_group_id.to_string(),
                policy: policy.to_string(),
                description: description.to_string(),
                priority,
                ipv6_source_cidr_ip: "".to_string(),
                port_range: port_range.to_string(),
                source_cidr_ip: ip.to_string(),
                ip_protocol: ip_protocol.to_string(),
                security_group_rule_id: security_group_rule_id.to_string(),
            }
        } else {
            Self {
                region_id: region_id.to_string(),
                security_group_id: security_group_id.to_string(),
                policy: policy.to_string(),
                description: description.to_string(),
                priority,
                ipv6_source_cidr_ip: ip.to_string(),
                port_range: port_range.to_string(),
                source_cidr_ip: "".to_string(),
                ip_protocol: ip_protocol.to_string(),
                security_group_rule_id: security_group_rule_id.to_string(),
            }
        }
    }

    pub fn to_vec(&self) -> Vec<(String, String)> {
        let mut v = vec![];
        v.push(("RegionId".to_string(), self.region_id.to_string()));
        v.push(("SecurityGroupId".to_string(), self.security_group_id.to_string()));
        v.push(("SecurityGroupRuleId".to_string(), self.security_group_rule_id.to_string()));
        v.push(("Policy".to_string(), self.policy.to_string()));
        v.push(("Description".to_string(), self.description.to_string()));
        v.push(("Priority".to_string(), self.priority.to_string()));
        v.push(("Ipv6SourceCidrIp".to_string(), self.ipv6_source_cidr_ip.to_string()));
        v.push(("PortRange".to_string(), self.port_range.to_string()));
        v.push(("IpProtocol".to_string(), self.ip_protocol.to_string()));
        v.push(("SourceCidrIp".to_string(), self.source_cidr_ip.to_string()));
        v
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseDescribeSecurityGroupAttribute {
    pub description: String,
    pub vpc_id: String,
    pub request_id: String,
    pub security_group_name: String,
    pub security_group_id: String,
    pub inner_access_policy: String,
    pub region_id: String,
    pub permissions: DescribeSecurityGroupAttributePermissions
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DescribeSecurityGroupAttributePermissions {
    pub permission: Vec<SecurityGroupPermission>,
}

impl DescribeSecurityGroupAttributePermissions {
    pub fn search_sg_by_ip(&self, ip: &str) -> Vec<SecurityGroupPermission> {
        let mut permissions = Vec::new();
        // println!("self debug {:?}", self.permission);
        let _: Vec<_> = self.permission.iter().map(|p| {
            // println!("p debug {:?}", p);
            // check ip type
            if IpAddr::from_str(&ip).unwrap().is_ipv4() {
                if ip == p.source_cidr_ip {
                    permissions.push(p.clone());
                }
            } else {
                if ip == p.ipv6_source_cidr_ip {
                    permissions.push(p.clone());
                }
            }
        }).collect();
        println!("find permissions: {permissions:?}");
        permissions
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SecurityGroupPermission {
    pub policy: String,
    pub description: String,
    pub priority: i32,
    pub ipv6_source_cidr_ip: String,
    pub port_range: String,
    pub source_cidr_ip: String,
    pub ip_protocol: String,
    pub security_group_rule_id: String,
}

impl SecurityGroupPermission {
    pub fn new (policy: &str, description: &str, ip: &str, port_range: &str, ip_protocol: &str) -> Self {
        // check ip is ipv4 or ipv6
        if IpAddr::from_str(&ip).unwrap().is_ipv4() {
            Self {
                policy: policy.to_string(),
                description: description.to_string(),
                priority: 100,
                ipv6_source_cidr_ip: "".to_string(),
                port_range: port_range.to_string(),
                source_cidr_ip: ip.to_string(),
                ip_protocol: ip_protocol.to_string(),
                security_group_rule_id: "".to_string(),
            }
        } else {
            Self {
                policy: policy.to_string(),
                description: description.to_string(),
                priority: 100,
                ipv6_source_cidr_ip: ip.to_string(),
                port_range: port_range.to_string(),
                source_cidr_ip: "".to_string(),
                ip_protocol: ip_protocol.to_string(),
                security_group_rule_id: "".to_string(),
            }
        }
    }

    pub fn is_match(&self, ip: &str, port_range: &str) -> bool {
        println!("ip: {} ?? {ip}, port_range: {} ?? {port_range}", self.source_cidr_ip, self.port_range);
        (self.source_cidr_ip == ip ) && (self.port_range == port_range)
    }

    pub fn is_expired(&self) -> bool {
        if &self.description.len() < &10 {
            return false;
        }
        let msg = &self.description[0..9];
        if msg != "valid_to:" {
            return false;
        }
        let rfc3339_str = &self.description[9..];
        //println!("rfc3339_str: {}", rfc3339_str);
        // let valid_to = chrono::DateTime::parse_from_rfc3339(rfc3339_str).unwrap().with_timezone(&Utc);
        let valid_to = chrono::DateTime::parse_from_rfc3339(rfc3339_str);
        if valid_to.is_err() {
            return false;
        }
        let valid_to = valid_to.unwrap().with_timezone(&Utc);
        let now = chrono::Utc::now();
        println!("{} valid_to: {}, now: {}", self.security_group_rule_id, valid_to, now);
        now > valid_to
    }

    pub fn set_expired(&mut self, duration: Duration) {
        let now = chrono::Utc::now();
        let valid_to = now + duration;
        self.description = format!("valid_to:{}", valid_to.to_rfc3339());
    }
}


impl AliyunCFG {
    pub fn new(access_key: &str, access_secret: &str, region_id: &str) -> Self {
        Self {
            rpc_client: RPClient::new(access_key, access_secret, "https://ecs.aliyuncs.com/"),
            region_id: region_id.to_string(),
        }
    }

    pub async fn add_whitelist(&self, sg_id: &str, ip: &str, port_range: Vec<String> ,duration: Duration) -> Result<String> {
        if ip == "127.0.0.1" {
            return Ok("127.0.0.1 do nothing".to_string());
        }
        // for test
        // let ip = "58.37.167.90";
        let mut res_str = "Done ".to_string();
        // 一个ip一定会存在多个记录
        // check if ip is already in whitelist
        // let mut permissions: Vec<SecurityGroupPermission>;
        let perms = self.get_whitelist_with_ip(sg_id, ip).await?;
        // 不存在的添加
        let mut existed = Vec::new();
        let _: Vec<_> = perms.iter().map(|p| {
            existed.push(format!("{}:{}:{}", ip, p.ip_protocol ,p.port_range));
        }).collect();
        println!("existed: {existed:?}");
        let mut permissions = Vec::new();
        for port_str in port_range {
            let port_str_split  = port_str.split(":");
            let port_split: Vec<&str> = port_str_split.collect();
            if port_split.len() < 2 {
                println!("port range format error, TCP|UDP:port_start/port_end");
                continue;
            }
            let port = port_split[1].to_string();
            let ip_protocol = port_split[0].to_string().to_uppercase();
            // 初始化情况，perms = 0 
            if perms.len() == 0 {
                let ex = format!("{ip}:{ip_protocol}:{port}");
                if !existed.contains(&ex) {
                    res_str += &format!("Add {ex} ");
                    let mut p = SecurityGroupPermission::new(
                        "Accept",
                        "",
                        ip,
                        &port,
                        &ip_protocol
                    );
                    p.set_expired(duration);
                    permissions.push(p);
                    existed.push(ex);
                }
            }
            for perm in &perms {
                if perm.is_match(ip, &port) {
                    // 有，更新
                    res_str += &format!("Update {}:{} {} ", ip, port, self.update_whitelist(sg_id, ip, perm.clone(), duration).await?);
                } else {
                    // 没有，添加
                    let ex = format!("{ip}:{ip_protocol}:{port}");
                    if !existed.contains(&ex) {
                        res_str += &format!("Add {ex} ");
                        let mut p = SecurityGroupPermission::new(
                            "Accept",
                            "",
                            ip,
                            &port,
                            &ip_protocol
                        );
                        p.set_expired(duration);
                        permissions.push(p);
                        existed.push(ex);
                    }
                }
            }
        }
        if permissions.len() > 0 {
            let query_params = RequestAuthorizeSecurityGroup::new(&self.region_id, sg_id, permissions).to_vec();
            println!("query_params: {query_params:?}");
            let result = &self.rpc_client.clone()
                .version("2014-05-26")
                .post("AuthorizeSecurityGroup")
                .query(query_params)
                .text()
                .await?;

            println!("{result:?}");
            res_str += result;
        }
        Ok(res_str)
    }

    pub async fn update_whitelist(&self, sg_id: &str, ip: &str, mut perms: SecurityGroupPermission, duration: Duration) -> Result<String> {
        let mut res_str = String::new();
        perms.set_expired(duration);
        // do update
        let req = RequestModifySecurityGroupRule::new(
            &self.region_id,
            sg_id,
            &perms.security_group_rule_id,
            &perms.policy,
            &perms.description,
            ip,
            &perms.port_range,
            &perms.ip_protocol,
            perms.priority
        );
        let query_params = req.to_vec();
        println!("update_whitelist query_params: {query_params:?}");
        let result = &self.rpc_client.clone()
            .version("2014-05-26")
            .post("ModifySecurityGroupRule")
            .query(query_params)
            .text()
            .await?;
        res_str.push_str(result);
        // 等待1秒
        // sleep(TokioDuration::from_secs(1)).await;
        Ok(res_str)
    }

    pub async fn clean_whitelist(&self, sg_id: &str, rule_id: &str) -> Result<()> {
        println!("clean_whitelist sg_id: {sg_id}, rule_id: {rule_id}");
        let res = self.rpc_client.clone()
            .version("2014-05-26")
            .post("RevokeSecurityGroup")
            .query([("RegionId", self.region_id.as_str()), ("SecurityGroupId", sg_id), ("SecurityGroupRuleId.1", rule_id)])
            .text()
            .await?;
        println!("clean_whitelist result: {res}");
        Ok(())
    }

    pub async fn get_whitelist_with_ip(&self, sg_id: &str, ip: &str) -> Result<Vec<SecurityGroupPermission>> {
        Ok(self.get_whitelist(sg_id).await?.permissions.search_sg_by_ip(ip))
    }

    pub async fn get_whitelist(&self, sg_id: &str) -> Result<ResponseDescribeSecurityGroupAttribute> {
        let result = &self.rpc_client.clone()
            .version("2014-05-26")
            .get("DescribeSecurityGroupAttribute")
            .query([("RegionId", self.region_id.as_str()), ("SecurityGroupId", sg_id)])
            .json::<ResponseDescribeSecurityGroupAttribute>()
            .await?;
        Ok(result.to_owned())
    }

}

