#!/bin/sh
# AgileNet 深度链路 E2E 测试脚本（在 tester 容器内执行）
# 统一签发世界：消费凭据 = direct 委托令牌（entry_mode=direct 直连签发者 listener、
# dedicated 全量路由、multi 多端并存）；扇入 relay 令牌与链式扇出（advertise 路由）不变。
# 组标语义：签发者 listener 按令牌 ACL 快照执法；组标只在「下一跳=签发者会话」时保留，
# 向普通下游转发一律干净 Open（下游无需任何同名组仪式）。
# 断言矩阵：
#   T1  客户端 → root → mid → leaf → deep → target (SOCKS5, 四级链)
#   T2  同目标经 HTTP CONNECT 代理
#   T3  ACL 拒绝：访问规则外目标必须失败
#   T4  多节点接入：同一客户端同时接 root 与 mid，目标两种路径均可达
#   T5  规则热更新：root 组新增 10.150.0.0/16，客户端【不重连】即放行新目标
#       （签发者侧 watcher 热刷注册表 + listener 每次 Open 热重建 ACL 路由器）
#   T6  断链自愈：kick mid → 链路中断 → 自动重连恢复
#   T7  管理面发现：mid 经握手自动发现 root 控制端点（status.manageable_upstreams，rules 档）
#       ——票据链换取 scoped 会话由 Rust 集成测试 control_plane_test 覆盖（REST 按设计不落票据）
#   T8  bandwidth 链路吞吐（mid → root 上游，经扇出隧道）
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

# $1=token $2=api $3=group_id $4=label → echoes delegated token plaintext (psk_, shown once)
# Unified issuance: direct entry (consumer dials the issuer's own listener), dedicated
# full-route, multi concurrency.
issue_delegated() {
  curl -sf -X POST "$2/api/v1/admin/delegation/tokens" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"label\":\"$4\",\"group_ids\":[\"$3\"],\"regs\":[],\"mode\":\"dedicated\",\"admin_scope\":\"\",\"entry_mode\":\"direct\",\"concurrency\":\"multi\"}" | jq -r '.data.token'
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

# ---------- 在 root 上准备组/规则/委托令牌 ----------
log "root: 创建组/规则/签发 direct 委托令牌"
ADMIN_TOKEN=$(admin_login "$ROOT_API")
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || { bad "root 管理员登录失败"; exit 1; }

GID=$(create_group "$ADMIN_TOKEN" "$ROOT_API" "chain组")
RID=$(create_rule "$ADMIN_TOKEN" "$ROOT_API" "10.140.0.0/16")
curl -sf -X PUT "$ROOT_API/api/v1/admin/groups/$GID/rules" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID\"]}" > /dev/null
TOK=$(issue_delegated "$ADMIN_TOKEN" "$ROOT_API" "$GID" "chainuser")
[ -n "$TOK" ] && [ "$TOK" != "null" ] && ok "root 委托令牌已签发（direct/dedicated/multi）" || { bad "root 委托令牌签发失败"; exit 1; }

# ---------- 在 mid 上准备组/规则/委托令牌（T4 用） ----------
log "mid: 创建组/规则/签发 direct 委托令牌"
MID_TOKEN=$(admin_login "$MID_API")
GID2=$(create_group "$MID_TOKEN" "$MID_API" "chain组")
RID2=$(create_rule "$MID_TOKEN" "$MID_API" "10.140.0.0/16")
curl -sf -X PUT "$MID_API/api/v1/admin/groups/$GID2/rules" \
  -H "Authorization: Bearer $MID_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID2\"]}" > /dev/null
TOK2=$(issue_delegated "$MID_TOKEN" "$MID_API" "$GID2" "chainuser2")
[ -n "$TOK2" ] && [ "$TOK2" != "null" ] && ok "mid 委托令牌已签发" || bad "mid 委托令牌签发失败"

# ---------- 启动客户端（连接 root） ----------
log "启动 anet-svc client（连接 root）..."
cat > /tmp/client.toml <<EOF
proxy_port = 57890
nodes = ["anet://connect?server=node-root&port=54430&account=d:chainuser&password=$TOK&insecure=1"]
EOF
anet-svc client /tmp/client.toml > /tmp/client.log 2>&1 &
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
nodes = [
  "anet://connect?server=node-root&port=54430&account=d:chainuser&password=$TOK&insecure=1",
  "anet://connect?server=node-mid&port=54430&account=d:chainuser2&password=$TOK2&insecure=1",
]
EOF
kill $CLIENT_PID 2>/dev/null || true
sleep 1
anet-svc client /tmp/client.toml > /tmp/client2.log 2>&1 &
CLIENT_PID=$!
sleep 5
if curl -sf --max-time 20 --socks5-hostname 127.0.0.1:57891 http://10.140.0.100/ | grep -q "Welcome to nginx"; then
  ok "T4 多节点合并路由下目标可达"
else
  bad "T4 多节点合并路由失败"
  tail -20 /tmp/client2.log
fi

# ---------- T5: 规则热更新（签发者侧 ACL 快照热刷，客户端不重连） ----------
# target2 (10.150.0.100) 仅在 deep2-net 可达；10.150.0.0/16 的路由经链式 advertise 静态存在，
# 但 root 组规则未覆盖 → 先被签发者 ACL 拒绝；新增规则后无需重连即放行。
log "T5: root 组新增 10.150.0.0/16 规则，客户端不重连访问 target2"
if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:57891 http://10.150.0.100/ > /dev/null 2>&1; then
  bad "T5a 前置异常：规则未加前 target2 竟可达"
else
  ok "T5a 规则未加前 target2 被 ACL 正确拒绝"
fi
RID3=$(create_rule "$ADMIN_TOKEN" "$ROOT_API" "10.150.0.0/16")
curl -sf -X PUT "$ROOT_API/api/v1/admin/groups/$GID/rules" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"rule_ids\":[\"$RID\",\"$RID3\"]}" > /dev/null
HOT=0
i=0
while [ $i -lt 8 ]; do
  sleep 3
  if curl -sf --max-time 8 --socks5-hostname 127.0.0.1:57891 http://10.150.0.100/ | grep -q "Welcome to nginx"; then
    HOT=1
    break
  fi
  i=$((i+1))
done
if [ "$HOT" = "1" ]; then
  ok "T5b 规则热更新生效（$(( (i+1)*3 ))s 内放行，客户端未重连）"
else
  bad "T5b 24s 内新规则未生效"
  tail -20 /tmp/client2.log
fi

# ---------- T7: 管理面发现（握手自动发现 root 控制端点） ----------
log "T7: mid 自动发现 root 控制端点（manageable_upstreams）"
MG=$(curl -sf "$MID_API/api/v1/admin/node/status" -H "Authorization: Bearer $MID_TOKEN" | \
  jq -r '[.data.manageable_upstreams[]? | .node_name + ":" + .scope] | join(",")')
case "$MG" in
  *node-root:rules*) ok "T7 可管理上游自动发现（manageable=$MG）";;
  *) bad "T7 未发现可管理上游（manageable=$MG）";;
esac

# ---------- T8: bandwidth 链路吞吐（mid → root 上游，经扇出隧道） ----------
log "T8: bandwidth — mid 经扇出隧道测 root（RTT/上下行吞吐）"
BW=$(curl -sf --max-time 120 -X POST "$MID_API/api/v1/admin/tool/bandwidth" \
  -H "Authorization: Bearer $MID_TOKEN" -H 'Content-Type: application/json' -d '{}')
if [ -n "$BW" ] && [ "$(echo "$BW" | jq -r '.code')" = "0" ]; then
  BW_PEER=$(echo "$BW" | jq -r '.data.peer')
  RTT_AVG=$(echo "$BW" | jq -r '.data.rtt.avg_ms')
  UP_MBPS=$(echo "$BW" | jq -r '.data.up.mbps')
  DOWN_MBPS=$(echo "$BW" | jq -r '.data.down.mbps')
  log "  bandwidth 结果: peer=$BW_PEER rtt.avg=${RTT_AVG}ms up=${UP_MBPS}Mbps down=${DOWN_MBPS}Mbps"
  # 量级断言：docker 桥接一跳隧道应远大于 10 Mbps；上下行字节数必须精确（8MiB）
  BW_OK=$(echo "$BW" | jq -r 'if (.data.up.mbps > 10 and .data.down.mbps > 10 and .data.up.bytes == 8388608 and .data.down.bytes == 8388608 and .data.rtt.avg_ms >= 0) then 1 else 0 end')
  if [ "$BW_OK" = "1" ]; then
    ok "T8 bandwidth 链路吞吐量级合理（peer/rtt/up/down 结构化返回）"
  else
    bad "T8 bandwidth 返回量级异常: $BW"
  fi
else
  bad "T8 bandwidth API 调用失败: $BW"
fi

# ---------- 汇总 ----------
kill $CLIENT_PID 2>/dev/null || true
echo ""
echo "════════════════════════════════"
echo "  链路测试结果: PASS=$PASS FAIL=$FAIL"
echo "════════════════════════════════"
[ "$FAIL" -eq 0 ]
