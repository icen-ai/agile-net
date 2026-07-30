#!/bin/sh
# AgileNet 深度链路 E2E 测试脚本（在 tester 容器内执行）
# 断言矩阵：
#   T1  客户端 → root → mid → leaf → deep → target (SOCKS5, 四级链)
#   T2  同目标经 HTTP CONNECT 代理
#   T3  ACL 拒绝：访问规则外目标必须失败
#   T4  多节点接入：同一客户端同时接 root 与 mid，目标两种路径均可达
#   T5  长轮询配置热更新：新增规则后客户端无需重连即生效
set -u

ROOT_API="http://node-root:9090"
MID_API="http://node-mid:9090"
ADMIN_PASS="ChainTest123!"
PASS=0
FAIL=0

log()  { echo "[chain-test] $*"; }
ok()   { PASS=$((PASS+1)); echo "  ✅ $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $*"; }

wait_api() {
  # $1 = api base
  i=0
  while [ $i -lt 60 ]; do
    if curl -sf "$1/" > /dev/null 2>&1; then return 0; fi
    i=$((i+1)); sleep 1
  done
  return 1
}

# $1=api $2=group_name → echoes group_id
create_group() {
  curl -sf -X POST "$1/api/v1/admin/groups" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\"}" | jq -r '.data.id'
}

# $1=api $2=value → echoes rule_id
create_rule() {
  curl -sf -X POST "$1/api/v1/admin/rules" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"type\":\"ip-cidr\",\"value\":\"$2\"}" | jq -r '.data.id'
}

# $1=api $2=group_id $3=username → echoes password
create_account() {
  curl -sf -X POST "$1/api/v1/admin/accounts" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$3\",\"group_id\":\"$2\"}" | jq -r '.data.password'
}

admin_login() {
  curl -sf -X POST "$1/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.data.access_token'
}

log "等待节点 API 就绪..."
wait_api "$ROOT_API" || { bad "root API 未就绪"; exit 1; }
wait_api "$MID_API"  || { bad "mid API 未就绪"; exit 1; }
log "API 全部就绪"

# 等待节点链建立（mid→root, leaf→mid, deep→leaf 的 relay 连接）
log "等待 relay 链路收敛..."
sleep 6

# ---------- 在 root 上准备账号 ----------
log "root: 创建组/规则/账号"
ADMIN_TOKEN=$(admin_login "$ROOT_API")
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || { bad "root 管理员登录失败"; exit 1; }

GID=$(create_group "$ROOT_API" "chain组")
RID=$(create_rule "$ROOT_API" "10.140.0.0/16")
curl -sf -X PUT "$ROOT_API/api/v1/admin/groups/$GID/rules" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID\"]}" > /dev/null
ACC_PASS=$(create_account "$ROOT_API" "$GID" "chainuser")
[ -n "$ACC_PASS" ] && [ "$ACC_PASS" != "null" ] && ok "root 账号已创建（sk- 强密码）" || { bad "root 账号创建失败"; exit 1; }

# ---------- 在 mid 上准备账号（T4 用） ----------
log "mid: 创建组/规则/账号"
MID_TOKEN=$(admin_login "$MID_API")
GID2=$(create_group "$MID_API" "chain组")
RID2=$(create_rule "$MID_API" "10.140.0.0/16")
curl -sf -X PUT "$MID_API/api/v1/admin/groups/$GID2/rules" \
  -H "Authorization: Bearer $MID_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID2\"]}" > /dev/null
ACC_PASS2=$(create_account "$MID_API" "$GID2" "chainuser2")
[ -n "$ACC_PASS2" ] && [ "$ACC_PASS2" != "null" ] && ok "mid 账号已创建" || bad "mid 账号创建失败"

# ---------- 启动客户端（连接 root） ----------
log "启动 agile-net-client（连接 root）..."
cat > /tmp/client.toml <<EOF
proxy_port = 7890

[[nodes]]
addr = "$ROOT_API"
username = "chainuser"
password = "$ACC_PASS"
insecure = true
EOF
agile-net-client /tmp/client.toml > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 4

# ---------- T1: SOCKS5 四级链 ----------
log "T1: SOCKS5 经 root→mid→leaf→deep 访问 10.140.0.100"
if curl -sf --max-time 20 --socks5-hostname 127.0.0.1:7890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T1 四级链路 SOCKS5 穿透成功"
else
  bad "T1 四级链路 SOCKS5 穿透失败"
  tail -20 /tmp/client.log
fi

# ---------- T2: HTTP CONNECT 四级链 ----------
log "T2: HTTP CONNECT 经同一链路访问"
if curl -sf --max-time 20 -x http://127.0.0.1:7890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T2 四级链路 HTTP CONNECT 穿透成功"
else
  bad "T2 四级链路 HTTP CONNECT 穿透失败"
fi

# ---------- T3: ACL 拒绝 ----------
log "T3: 访问规则外目标必须失败（ACL）"
if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:7890 http://10.200.0.1/ > /dev/null 2>&1; then
  bad "T3 ACL 失效：规则外目标竟然可达"
else
  ok "T3 ACL 正确拒绝规则外目标"
fi

# ---------- T4: 多节点同时接入 ----------
log "T4: 客户端同时接入 root 与 mid（合并路由）"
cat > /tmp/client.toml <<EOF
proxy_port = 7891

[[nodes]]
addr = "$ROOT_API"
username = "chainuser"
password = "$ACC_PASS"
insecure = true

[[nodes]]
addr = "$MID_API"
username = "chainuser2"
password = "$ACC_PASS2"
insecure = true
EOF
kill $CLIENT_PID 2>/dev/null || true
sleep 1
agile-net-client /tmp/client.toml > /tmp/client2.log 2>&1 &
CLIENT_PID=$!
sleep 5
if curl -sf --max-time 20 --socks5-hostname 127.0.0.1:7891 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T4 多节点合并路由下目标可达"
else
  bad "T4 多节点合并路由失败"
  tail -20 /tmp/client2.log
fi

# ---------- T5: 配置热更新（长轮询） ----------
log "T5: root 新增规则（10.120.0.0/16），客户端不重连即生效"
RID3=$(create_rule "$ROOT_API" "10.120.0.0/16")
curl -sf -X PUT "$ROOT_API/api/v1/admin/groups/$GID/rules" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID\",\"$RID3\"]}" > /dev/null
sleep 8
# 10.120.0.30 是 leaf（其 API 未对 tester 所在的 public-net 开放，链路内也不通）
# 但路由命中即可证明热更新生效：经 SOCKS 访问 leaf-net 内目标（预期连接失败但非 ACL 拒绝）
# 以 client 日志出现新配置版本为准
if grep -q "config updated" /tmp/client2.log; then
  ok "T5 长轮询热更新已推送（config updated）"
else
  # 容忍日志时序：再等等
  sleep 8
  if grep -q "config updated" /tmp/client2.log; then
    ok "T5 长轮询热更新已推送（第二轮检查）"
  else
    bad "T5 未观察到配置热更新"
    tail -20 /tmp/client2.log
  fi
fi

# ---------- 汇总 ----------
kill $CLIENT_PID 2>/dev/null || true
echo ""
echo "════════════════════════════════"
echo "  链路测试结果: PASS=$PASS FAIL=$FAIL"
echo "════════════════════════════════"
[ "$FAIL" -eq 0 ]
