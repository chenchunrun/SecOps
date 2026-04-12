# 高危端口参考表

## 远程访问类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 22 | SSH | 高 | 远程管理，暴力破解目标 |
| 23 | Telnet | 严重 | 明文传输，应禁用 |
| 3389 | RDP | 高 | Windows 远程桌面，勒索软件入口 |
| 5900 | VNC | 高 | 远程桌面，常有弱口令 |
| 5901-5910 | VNC | 高 | VNC 扩展端口 |

## 数据库类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 1433 | MSSQL | 严重 | SQL Server，不应暴露 |
| 1434 | MSSQL Browser | 高 | SQL Server 浏览器服务 |
| 3306 | MySQL | 严重 | MySQL，不应暴露 |
| 5432 | PostgreSQL | 严重 | PostgreSQL，不应暴露 |
| 27017 | MongoDB | 严重 | MongoDB，常见未授权访问 |
| 27018 | MongoDB | 严重 | MongoDB 分片服务 |
| 6379 | Redis | 严重 | Redis，常见未授权访问 |
| 11211 | Memcached | 高 | Memcached，可被利用 DDoS |
| 9200 | Elasticsearch | 严重 | ES，常见未授权访问 |
| 9300 | Elasticsearch | 高 | ES 集群通信 |
| 5984 | CouchDB | 高 | CouchDB |
| 8086 | InfluxDB | 高 | InfluxDB |
| 7474 | Neo4j | 高 | 图数据库 |

## 中间件类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 1099 | Java RMI | 高 | Java 远程调用，反序列化风险 |
| 1100 | RMI | 高 | RMI Registry |
| 2181 | ZooKeeper | 高 | 分布式协调服务 |
| 2375 | Docker | 严重 | Docker API，可接管主机 |
| 2376 | Docker TLS | 高 | Docker TLS API |
| 2379 | etcd | 严重 | K8s 存储，可泄露密钥 |
| 6443 | K8s API | 严重 | Kubernetes API |
| 10250 | Kubelet | 严重 | Kubelet API |
| 5672 | RabbitMQ | 中 | 消息队列 |
| 15672 | RabbitMQ | 高 | 管理界面 |
| 9092 | Kafka | 中 | 消息队列 |
| 50070 | HDFS | 高 | Hadoop NameNode |
| 50010 | HDFS | 中 | Hadoop DataNode |
| 8088 | YARN | 高 | Hadoop 资源管理 |

## 管理/监控类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 161 | SNMP | 中 | 网络管理，信息泄露 |
| 162 | SNMP Trap | 中 | SNMP 陷阱 |
| 514 | Syslog | 低 | 日志服务 |
| 3000 | Grafana | 中 | 监控面板 |
| 9090 | Prometheus | 中 | 监控系统 |
| 9093 | Alertmanager | 中 | 告警管理 |
| 5601 | Kibana | 中 | 日志分析 |
| 8500 | Consul | 高 | 服务发现 |
| 4646 | Nomad | 高 | 任务调度 |

## 开发/CI-CD 类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 8080 | Jenkins/Tomcat | 高 | CI/CD 或应用服务器 |
| 8443 | Jenkins TLS | 高 | CI/CD HTTPS |
| 9418 | Git | 中 | Git 协议 |
| 80/443 | GitLab | 中 | 代码仓库 |
| 5000 | Docker Registry | 高 | 镜像仓库 |
| 8081 | Nexus | 高 | 制品仓库 |
| 4873 | Verdaccio | 中 | npm 私有仓库 |

## 文件共享类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 21 | FTP | 高 | 文件传输，匿名访问 |
| 69 | TFTP | 高 | 简单文件传输 |
| 137-139 | NetBIOS | 高 | Windows 共享 |
| 445 | SMB | 严重 | 勒索软件传播渠道 |
| 111 | RPC | 中 | NFS RPC |
| 2049 | NFS | 高 | 网络文件系统 |
| 873 | Rsync | 高 | 可未授权访问 |

## 邮件类

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 25 | SMTP | 中 | 邮件发送 |
| 110 | POP3 | 中 | 邮件接收 |
| 143 | IMAP | 中 | 邮件接收 |
| 465 | SMTPS | 低 | 安全邮件发送 |
| 587 | Submission | 低 | 邮件提交 |
| 993 | IMAPS | 低 | 安全 IMAP |
| 995 | POP3S | 低 | 安全 POP3 |

## 处置建议

### 严重风险（立即处理）
1. 关闭公网访问
2. 如必须开放，配置 IP 白名单
3. 启用强认证机制

### 高风险（24小时内）
1. 评估是否必须暴露
2. 配置访问控制
3. 启用日志监控

### 中风险（本周处理）
1. 评估安全配置
2. 启用认证
3. 监控异常访问

## 快速检测命令

```bash
# 检测目标高危端口
nmap -sS -p 22,23,3306,3389,6379,27017,9200 target.com

# 批量检测
nmap -sS --top-ports 100 -iL targets.txt -oA scan_results
```
