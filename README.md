# Aliyun的whitelist me

故事背景，最近暴露了一些管理用的ssh端口，虽然这些端口使用了证书验证，但是反复被扫描暴破，所以决定搞个白名单自行添加的工具，思路类似敲门工具

## 使用前提需求

1. 阿里云某个svc帐号，权限如下

```json
{
    "Version": "1",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:AuthorizeSecurityGroup",
                "ecs:ModifySecurityGroupRule",
                "ecs:RevokeSecurityGroup",
                "ecs:DescribeSecurityGroupAttribute",
                "ecs:DescribeSecurityGroups"
            ],
            "Resource": "acs:ecs:*:{account_id}:securitygroup/{sg_id}}"
        }
    ]
}
```

部署这个服务，并运行

```
ALIYUN_ACCESS_KEY=abc ALIYUN_ACCESS_SECRET=xyz RUST_LOG=debug ALLOW_USER_PASS='{"aaa":"bbb", "x2x4": "1234"}' ALIYUN_VPC_SG_ID="sg-id" cargo run
```

访问 http://your-ip:3000/