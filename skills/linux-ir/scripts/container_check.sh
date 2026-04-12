#!/bin/bash
# Linux 容器安全检测脚本
# 检测 Docker/Kubernetes/Podman 环境安全问题
# 用法: bash container_check.sh

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  容器安全检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

ISSUES=0

#===============================================================================
# 0. 环境检测
#===============================================================================
print_section "0. 容器环境检测"

# 检测是否在容器内
echo -e "${YELLOW}[当前运行环境]${NC}"
IN_CONTAINER=false
CONTAINER_TYPE="none"

if [[ -f /.dockerenv ]]; then
    echo -e "${CYAN}[!] 当前在 Docker 容器内${NC}"
    IN_CONTAINER=true
    CONTAINER_TYPE="docker"
elif grep -q 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
    echo -e "${CYAN}[!] 当前在容器内 (cgroup 检测)${NC}"
    IN_CONTAINER=true
    CONTAINER_TYPE="container"
elif [[ -f /run/.containerenv ]]; then
    echo -e "${CYAN}[!] 当前在 Podman 容器内${NC}"
    IN_CONTAINER=true
    CONTAINER_TYPE="podman"
else
    echo "当前在宿主机上"
fi

# 检测 K8s 环境
if [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    echo -e "${CYAN}[!] 检测到 Kubernetes 环境${NC}"
    CONTAINER_TYPE="kubernetes"
fi

# 检测可用的容器运行时
echo -e "\n${YELLOW}[容器运行时]${NC}"
HAS_DOCKER=false
HAS_PODMAN=false
HAS_KUBECTL=false
HAS_CRICTL=false

command -v docker &>/dev/null && HAS_DOCKER=true && echo "  Docker: $(docker --version 2>/dev/null || echo '已安装')"
command -v podman &>/dev/null && HAS_PODMAN=true && echo "  Podman: $(podman --version 2>/dev/null || echo '已安装')"
command -v kubectl &>/dev/null && HAS_KUBECTL=true && echo "  kubectl: $(kubectl version --client --short 2>/dev/null || echo '已安装')"
command -v crictl &>/dev/null && HAS_CRICTL=true && echo "  crictl: $(crictl --version 2>/dev/null || echo '已安装')"

if ! $HAS_DOCKER && ! $HAS_PODMAN && ! $HAS_KUBECTL; then
    echo "  未检测到容器运行时"
fi

#===============================================================================
# 1. Docker 安全检测 (ATT&CK T1610, T1611)
#===============================================================================
if $HAS_DOCKER; then
    print_section "1. Docker 安全检测 [T1610, T1611]"

    echo -e "${YELLOW}[Docker 守护进程配置]${NC}"
    if [[ -r /etc/docker/daemon.json ]]; then
        echo "daemon.json 内容:"
        cat /etc/docker/daemon.json 2>/dev/null | head -20
    else
        echo "daemon.json 不存在或无权限"
    fi

    echo -e "\n${YELLOW}[Docker Socket 权限]${NC}"
    if [[ -S /var/run/docker.sock ]]; then
        ls -la /var/run/docker.sock
        # 检查非 root 用户是否可以访问
        sock_group=$(stat -c %G /var/run/docker.sock)
        echo "Socket 组: $sock_group"
        getent group "$sock_group" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read user; do
            [[ -n "$user" ]] && echo "  成员: $user"
        done
    else
        echo "Docker socket 不存在"
    fi

    echo -e "\n${YELLOW}[运行中的容器]${NC}"
    docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | head -15 || echo "无权限或无运行容器"

    echo -e "\n${YELLOW}[特权容器检测]${NC}"
    docker ps -q 2>/dev/null | while read cid; do
        privileged=$(docker inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
        if [[ "$privileged" == "true" ]]; then
            name=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null)
            echo -e "${RED}[!] 特权容器: $name ($cid)${NC}"
            ((ISSUES++))
        fi
    done || echo "检查完成"

    echo -e "\n${YELLOW}[危险挂载检测]${NC}"
    docker ps -q 2>/dev/null | while read cid; do
        mounts=$(docker inspect "$cid" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)
        name=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null)

        # 检查危险挂载
        for dangerous in "/:/host" "/etc:/etc" "/var/run/docker.sock" "/proc:/proc" "/sys:/sys"; do
            if echo "$mounts" | grep -q "$dangerous"; then
                echo -e "${RED}[!] $name: 危险挂载 $dangerous${NC}"
                ((ISSUES++))
            fi
        done
    done || echo "检查完成"

    echo -e "\n${YELLOW}[容器网络模式]${NC}"
    docker ps -q 2>/dev/null | while read cid; do
        netmode=$(docker inspect "$cid" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
        name=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null)
        if [[ "$netmode" == "host" ]]; then
            echo -e "${YELLOW}[!] $name: 使用 host 网络模式${NC}"
        fi
    done || echo "检查完成"

    echo -e "\n${YELLOW}[敏感环境变量]${NC}"
    docker ps -q 2>/dev/null | while read cid; do
        name=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null)
        envs=$(docker inspect "$cid" --format '{{range .Config.Env}}{{.}} {{end}}' 2>/dev/null)
        if echo "$envs" | grep -qiE 'password|secret|key|token|credential|api_key'; then
            echo -e "${YELLOW}[!] $name: 可能包含敏感环境变量${NC}"
        fi
    done || echo "检查完成"

    echo -e "\n${YELLOW}[可疑镜像]${NC}"
    # 可信镜像仓库白名单
    TRUSTED_REGISTRIES="ghcr.io docker.io gcr.io quay.io mcr.microsoft.com registry.k8s.io"
    found_suspicious=false
    docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | while read img; do
        # 跳过可信仓库的镜像
        skip=false
        for registry in $TRUSTED_REGISTRIES; do
            if [[ "$img" == "$registry"/* ]]; then
                skip=true
                break
            fi
        done
        $skip && continue

        # 检查可疑镜像名 (使用词边界避免误报)
        if echo "$img" | grep -qiE '\bhack\b|\bexploit\b|\bshell\b|\bbackdoor\b|\bminer\b|\bxmr\b'; then
            echo -e "${RED}[!] 可疑镜像: $img${NC}"
            found_suspicious=true
            ISSUES=$((ISSUES + 1))
        fi
    done
    $found_suspicious || echo "未发现可疑镜像"
fi

#===============================================================================
# 2. Kubernetes 安全检测 (ATT&CK T1609, T1610)
#===============================================================================
if $HAS_KUBECTL || [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    print_section "2. Kubernetes 安全检测 [T1609, T1610]"

    echo -e "${YELLOW}[集群信息]${NC}"
    kubectl cluster-info 2>/dev/null | head -5 || echo "无法获取集群信息"

    echo -e "\n${YELLOW}[当前上下文]${NC}"
    kubectl config current-context 2>/dev/null || echo "未配置"

    echo -e "\n${YELLOW}[ServiceAccount Token (容器内)]${NC}"
    if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        echo -e "${YELLOW}[!] 发现 ServiceAccount Token${NC}"
        echo "  路径: /var/run/secrets/kubernetes.io/serviceaccount/"
        ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
    else
        echo "未发现 (非 K8s Pod 或已禁用)"
    fi

    echo -e "\n${YELLOW}[特权 Pod 检测]${NC}"
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | \
        head -10 || echo "无法检测或无特权 Pod"

    echo -e "\n${YELLOW}[hostPath 挂载检测]${NC}"
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.volumes[]?.hostPath != null) | "\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[].hostPath.path)"' 2>/dev/null | \
        head -10 || echo "无法检测"

    echo -e "\n${YELLOW}[hostNetwork Pod]${NC}"
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | \
        head -10 || echo "无法检测"

    echo -e "\n${YELLOW}[RBAC - ClusterRoleBindings (cluster-admin)]${NC}"
    kubectl get clusterrolebindings -o json 2>/dev/null | \
        jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name + ": " + (.subjects[]?.name // "unknown")' 2>/dev/null | \
        head -10 || echo "无法检测"
fi

#===============================================================================
# 3. 容器逃逸检测 (ATT&CK T1611)
#===============================================================================
if $IN_CONTAINER; then
    print_section "3. 容器逃逸风险检测 [T1611]"

    echo -e "${YELLOW}[Capabilities 检查]${NC}"
    if [[ -r /proc/self/status ]]; then
        cap_eff=$(grep CapEff /proc/self/status | awk '{print $2}')
        echo "CapEff: $cap_eff"

        # 解析危险 capabilities
        cap_decoded=$(capsh --decode="$cap_eff" 2>/dev/null || echo "无法解析")
        echo "解析: $cap_decoded"

        # 检查危险 capability
        for dangerous_cap in "cap_sys_admin" "cap_sys_ptrace" "cap_sys_module" "cap_dac_override" "cap_net_admin"; do
            if echo "$cap_decoded" | grep -qi "$dangerous_cap"; then
                echo -e "${RED}[!] 危险 Capability: $dangerous_cap${NC}"
                ((ISSUES++))
            fi
        done
    fi

    echo -e "\n${YELLOW}[/proc 挂载检查]${NC}"
    if [[ -w /proc/sys/kernel/core_pattern ]]; then
        echo -e "${RED}[!] /proc/sys/kernel/core_pattern 可写 - 可能可以逃逸!${NC}"
        ((ISSUES++))
    else
        echo "/proc/sys/kernel/core_pattern 只读 (正常)"
    fi

    echo -e "\n${YELLOW}[cgroup 逃逸检查]${NC}"
    if [[ -w /sys/fs/cgroup ]]; then
        echo -e "${YELLOW}[!] /sys/fs/cgroup 可写${NC}"
    else
        echo "/sys/fs/cgroup 只读 (正常)"
    fi

    echo -e "\n${YELLOW}[设备访问检查]${NC}"
    for dev in /dev/sda /dev/vda /dev/xvda /dev/nvme0n1; do
        if [[ -r "$dev" ]]; then
            echo -e "${RED}[!] 可读取宿主机磁盘: $dev${NC}"
            ((ISSUES++))
        fi
    done

    echo -e "\n${YELLOW}[Docker Socket 检查]${NC}"
    if [[ -S /var/run/docker.sock ]]; then
        echo -e "${RED}[!] Docker socket 已挂载 - 可以控制宿主机 Docker!${NC}"
        ((ISSUES++))
    else
        echo "Docker socket 未挂载 (正常)"
    fi

    echo -e "\n${YELLOW}[已知逃逸漏洞检查]${NC}"
    # 检查内核版本 (CVE-2022-0185, CVE-2022-0847)
    kernel_version=$(uname -r)
    echo "内核版本: $kernel_version"

    # 简单版本检查
    kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
    if [[ "$kernel_major" -lt 5 ]] || [[ "$kernel_major" -eq 5 && "$kernel_minor" -lt 16 ]]; then
        echo -e "${YELLOW}[!] 内核版本较旧，可能受 Dirty Pipe (CVE-2022-0847) 等漏洞影响${NC}"
    fi
fi

#===============================================================================
# 4. 云 Metadata 服务检测 (ATT&CK T1552.005)
#===============================================================================
print_section "4. 云 Metadata 服务检测 [T1552.005]"

echo -e "${YELLOW}[云环境检测]${NC}"
CLOUD_ENV="unknown"

# AWS
if curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
    echo -e "${CYAN}[!] AWS Metadata 服务可访问${NC}"
    CLOUD_ENV="aws"
    echo "Instance ID: $(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'N/A')"

    # 检查 IAM 角色
    role=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
    if [[ -n "$role" ]]; then
        echo -e "${YELLOW}[!] 发现 IAM 角色: $role${NC}"
    fi
fi

# GCP
if curl -s --connect-timeout 1 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
    echo -e "${CYAN}[!] GCP Metadata 服务可访问${NC}"
    CLOUD_ENV="gcp"
fi

# Azure
if curl -s --connect-timeout 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
    echo -e "${CYAN}[!] Azure Metadata 服务可访问${NC}"
    CLOUD_ENV="azure"
fi

if [[ "$CLOUD_ENV" == "unknown" ]]; then
    echo "未检测到云 Metadata 服务 (非云环境或已禁用)"
fi

#===============================================================================
# 5. 容器镜像安全
#===============================================================================
if $HAS_DOCKER; then
    print_section "5. 容器镜像安全"

    echo -e "${YELLOW}[最近拉取的镜像]${NC}"
    docker images --format "{{.Repository}}:{{.Tag}}\t{{.CreatedSince}}\t{{.Size}}" 2>/dev/null | head -10 || echo "无法获取"

    echo -e "\n${YELLOW}[无标签镜像 (dangling)]${NC}"
    docker images -f "dangling=true" -q 2>/dev/null | wc -l | xargs -I {} echo "{} 个无标签镜像"

    echo -e "\n${YELLOW}[大于 1GB 的镜像]${NC}"
    docker images --format "{{.Repository}}:{{.Tag}}\t{{.Size}}" 2>/dev/null | \
        awk -F'\t' '{
            size=$2;
            if (match(size, /([0-9.]+)GB/, arr) && arr[1] > 1) print $1 "\t" size
        }' | head -5 || echo "未发现"
fi

#===============================================================================
# 总结
#===============================================================================
print_section "检测完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "环境类型: $CONTAINER_TYPE"
echo ""
if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[!] 发现 $ISSUES 项安全问题${NC}"
else
    echo -e "${GREEN}[✓] 未发现明显安全问题${NC}"
fi
echo ""
echo -e "${YELLOW}容器安全 ATT&CK 映射:${NC}"
echo "  T1609     - Container Administration Command"
echo "  T1610     - Deploy Container"
echo "  T1611     - Escape to Host"
echo "  T1552.005 - Cloud Instance Metadata API"
echo "  T1613     - Container and Resource Discovery"
