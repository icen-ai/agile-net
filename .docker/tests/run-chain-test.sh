#!/bin/sh
# AgileNet 深度链路 E2E 测试脚本（在 tester 容器内执行）
# 断言矩阵：
#   T1  客户端 → root → mid → leaf → deep → target (SOCKS5, 四级链)
#   T2  同目标经 HTTP CONNECT 代理
#   T3  ACL 拒绝：访问规则外目标必须失败
#   T4  多节点接入：同一客户端同时接 root 与 mid，目标两种路径均可达
#   T5  长轮询配置热更新：新增规则后客户端无需重连即生效
#   T6  断链自愈：kick mid → 链路中断 → 自动重连恢复
#   T7  管理面穿透：握手 v2 控制端点发现 + 票据链换取 scoped 管理会话（rules 档位强制）
set -u

ROOT_API="http://node-root:59090"
MID_API="http://node-mid:59090"
ADMIN_PASS="ChainTest123!"
PASS=0
FAIL=0

log()  { echo "[chain-test] $*"; }
ok()   { PASS=$((PASS+1)); echo "  [PASS] $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  [FAIL] $*"; }

wait_api() {
  # $1 = api base
  i=0
  while [ $i -lt 60 ]; do
    if curl -sf "$1/" > /dev/null 2>&1; then return 0; fi
    i=$((i+1)); sleep 1
  done
  return 1
}

# $1=token $2=api $3=group_name → echoes group_id
create_group() {
  curl -sf -X POST "$2/api/v1/admin/groups" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$3\"}" | jq -r '.data.id'
}

# $1=token $2=api $3=value → echoes rule_id
create_rule() {
  curl -sf -X POST "$2/api/v1/admin/rules" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"type\":\"ip-cidr\",\"value\":\"$3\"}" | jq -r '.data.id'
}

# $1=token $2=api $3=group_id $4=username → echoes password
create_account() {
  curl -sf -X POST "$2/api/v1/admin/accounts" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$4\",\"group_id\":\"$3\"}" | jq -r '.data.password'
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

GID=$(create_group "$ADMIN_TOKEN" "$ROOT_API" "chain组")
RID=$(create_rule "$ADMIN_TOKEN" "$ROOT_API" "10.140.0.0/16")
curl -sf -X PUT "$ROOT_API/api/v1/admin/groups/$GID/rules" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID\"]}" > /dev/null
ACC_PASS=$(create_account "$ADMIN_TOKEN" "$ROOT_API" "$GID" "chainuser")
[ -n "$ACC_PASS" ] && [ "$ACC_PASS" != "null" ] && ok "root 账号已创建（sk- 强密码）" || { bad "root 账号创建失败"; exit 1; }

# ---------- 在 mid 上准备账号（T4 用） ----------
log "mid: 创建组/规则/账号"
MID_TOKEN=$(admin_login "$MID_API")
GID2=$(create_group "$MID_TOKEN" "$MID_API" "chain组")
RID2=$(create_rule "$MID_TOKEN" "$MID_API" "10.140.0.0/16")
curl -sf -X PUT "$MID_API/api/v1/admin/groups/$GID2/rules" \
  -H "Authorization: Bearer $MID_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID2\"]}" > /dev/null
ACC_PASS2=$(create_account "$MID_TOKEN" "$MID_API" "$GID2" "chainuser2")
[ -n "$ACC_PASS2" ] && [ "$ACC_PASS2" != "null" ] && ok "mid 账号已创建" || bad "mid 账号创建失败"

# ---------- 启动客户端（连接 root） ----------
log "启动 agile-net-client（连接 root）..."
cat > /tmp/client.toml <<EOF
proxy_port = 57890

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
if curl -sf --max-time 20 --socks5-hostname 127.0.0.1:57890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T1 四级链路 SOCKS5 穿透成功"
else
  bad "T1 四级链路 SOCKS5 穿透失败"
  tail -20 /tmp/client.log
fi

# ---------- T2: HTTP CONNECT 四级链 ----------
log "T2: HTTP CONNECT 经同一链路访问"
if curl -sf --max-time 20 -x http://127.0.0.1:57890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T2 四级链路 HTTP CONNECT 穿透成功"
else
  bad "T2 四级链路 HTTP CONNECT 穿透失败"
fi

# ---------- T3: ACL 拒绝 ----------
log "T3: 访问规则外目标必须失败（ACL）"
if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:57890 http://10.200.0.1/ > /dev/null 2>&1; then
  bad "T3 ACL 失效：规则外目标竟然可达"
else
  ok "T3 ACL 正确拒绝规则外目标"
fi

# ---------- T6: 断链自愈（kick mid → 链路中断 → 自动重连恢复） ----------
log "T6: 断链自愈 — kick node-mid 后链路中断再自动恢复"
# 6a. 先确认链路可用
if curl -sf --max-time 15 --socks5-hostname 127.0.0.1:57890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T6a kick 前链路可用"
else
  bad "T6a kick 前链路已不可用（前置失败）"
fi
# 6b. root 踢掉 node-mid → 链路必须中断
curl -sf -X POST "$ROOT_API/api/v1/admin/node/kick" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"node_id":"node-mid"}' > /dev/null || bad "T6 kick 接口调用失败"
sleep 3
if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:57890 http://10.140.0.100/ > /dev/null 2>&1; then
  bad "T6b kick 后链路仍然可用（断开未生效）"
else
  ok "T6b kick 后链路按预期中断"
fi
# 6c. node-mid 自动重连（指数退避 ≤ ~8s）后链路必须恢复
RECOVERED=0
i=0
while [ $i -lt 10 ]; do
  sleep 3
  if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:57890 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
    RECOVERED=1
    break
  fi
  i=$((i+1))
done
if [ "$RECOVERED" = "1" ]; then
  ok "T6c 链路自动恢复（$(( (i+1)*3 ))s 内重连成功）"
else
  bad "T6c 30s 内链路未自愈"
fi

# ---------- T4: 多节点同时接入 ----------
log "T4: 客户端同时接入 root 与 mid（合并路由）"
cat > /tmp/client.toml <<EOF
proxy_port = 57891

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
if curl -sf --max-time 20 --socks5-hostname 127.0.0.1:57891 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T4 多节点合并路由下目标可达"
else
  bad "T4 多节点合并路由失败"
  tail -20 /tmp/client2.log
fi

# ---------- T5: 配置热更新（长轮询） ----------
log "T5: root 新增规则（10.120.0.0/16），客户端不重连即生效"
RID3=$(create_rule "$ADMIN_TOKEN" "$ROOT_API" "10.120.0.0/16")
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

# ---------- T7: 管理面穿透（握手 v2 控制端点发现 + 票据链换取 scoped 管理会话） ----------
log "T7: 管理面穿透 — mid 发现 root 控制端点，客户端经隧道管理 root"
# T7a. mid 上创建管理版账号（admin_console）
GID3=$(create_group "$MID_TOKEN" "$MID_API" "ops组")
ACC_PASS3=$(curl -sf -X POST "$MID_API/api/v1/admin/accounts" \
  -H "Authorization: Bearer $MID_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"username\":\"chainadmin\",\"group_id\":\"$GID3\",\"admin_console\":true}" | jq -r '.data.password')
[ -n "$ACC_PASS3" ] && [ "$ACC_PASS3" != "null" ] && ok "T7a 管理版账号已创建" || bad "T7a 管理版账号创建失败"

# T7b. 管理版客户端配置自动发现可管理上游（握手 v2：root 向 mid 暴露控制面）
CT=$(curl -sf -X POST "$MID_API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"chainadmin\",\"password\":\"$ACC_PASS3\"}" | jq -r '.data.access_token')
MG=$(curl -sf "$MID_API/api/v1/client/config" -H "Authorization: Bearer $CT" | jq -r '[.data.manageable[]?|.node_name]|join(",")')
case "$MG" in
  *node-root*) ok "T7b 可管理上游自动发现（manageable=$MG）";;
  *) bad "T7b 未发现可管理上游（manageable=$MG）";;
esac

# T7c. 取上游控制台票据（中继令牌换取，scoped）
TICKET=$(curl -sf -X POST "$MID_API/api/v1/client/console-ticket" \
  -H "Authorization: Bearer $CT" -H 'Content-Type: application/json' \
  -d '{"upstream":"node-root"}' | jq -r '.data.ticket // empty')
case "$TICKET" in
  adt_*) ok "T7c 上游控制台票据已签发";;
  *) bad "T7c 票据签发失败";;
esac

# T7d. 经数据面隧道（SOCKS5 → mid → root API）用票据换取 scoped 管理会话
cat > /tmp/client.toml <<EOF
proxy_port = 57892

[[nodes]]
addr = "$MID_API"
username = "chainadmin"
password = "$ACC_PASS3"
insecure = true
EOF
kill $CLIENT_PID 2>/dev/null || true
sleep 1
agile-net-client /tmp/client.toml > /tmp/client3.log 2>&1 &
CLIENT_PID=$!
sleep 4
BOOT=$(curl -sf --max-time 15 --socks5-hostname 127.0.0.1:57892 -X POST \
  "http://node-root:59090/api/v1/auth/admin-bootstrap" \
  -H 'Content-Type: application/json' -d "{\"ticket\":\"$TICKET\"}")
MJWT=$(echo "$BOOT" | jq -r '.data.access_token // empty')
MSCOPE=$(echo "$BOOT" | jq -r '.data.scope // empty')
if [ -n "$MJWT" ] && [ "$MSCOPE" = "rules" ]; then
  ok "T7d 隧道内票据换取 scoped 管理会话（scope=$MSCOPE）"
else
  bad "T7d 票据换取失败（$BOOT）"
  tail -10 /tmp/client3.log
fi

# T7e/T7f. scope 三档强制：rules 可读、组写被拒（403）
RC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --socks5-hostname 127.0.0.1:57892 \
  -H "Authorization: Bearer $MJWT" "http://node-root:59090/api/v1/admin/node/status")
[ "$RC" = "200" ] && ok "T7e rules 档位读取通过（200）" || bad "T7e 读取失败（$RC）"
RC2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --socks5-hostname 127.0.0.1:57892 -X POST \
  -H "Authorization: Bearer $MJWT" -H 'Content-Type: application/json' \
  -d '{"name":"should-deny"}' "http://node-root:59090/api/v1/admin/groups")
[ "$RC2" = "403" ] && ok "T7f rules 档位组写被拒（403）" || bad "T7f 组写未拒（$RC2）"

# ---------- 汇总 ----------
kill $CLIENT_PID 2>/dev/null || true
echo ""
echo "════════════════════════════════"
echo "  链路测试结果: PASS=$PASS FAIL=$FAIL"
echo "════════════════════════════════"
[ "$FAIL" -eq 0 ]
