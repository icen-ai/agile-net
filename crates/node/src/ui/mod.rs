//! Web 管理后台单页应用 (Admin Web UI)

use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};

const ADMIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgileNet Dashboard</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --danger: #ef4444;
            --success: #22c55e;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 20px; line-height: 1.5; }
        .container { max-width: 1100px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
        h1 { font-size: 1.5rem; color: var(--accent); display: flex; align-items: center; gap: 8px; }
        .nav { display: flex; gap: 12px; }
        button { background: var(--accent); color: #000; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: 0.2s; }
        button:hover { background: var(--accent-hover); color: #fff; }
        button.btn-danger { background: var(--danger); color: #fff; }
        button.btn-danger:hover { opacity: 0.8; }
        .card { background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border); padding: 20px; margin-bottom: 24px; }
        .card-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 16px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 12px; border-bottom: 1px solid var(--border); }
        th { color: var(--text-dim); font-weight: 500; font-size: 0.9rem; }
        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; display: inline-block; }
        .status-online { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .status-offline { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .form-group { display: flex; gap: 12px; margin-top: 16px; flex-wrap: wrap; }
        input, select { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 8px 12px; border-radius: 6px; flex: 1; min-width: 160px; }
        #login-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.9); display: flex; justify-content: center; align-items: center; z-index: 100; }
        .login-box { background: var(--card-bg); padding: 32px; border-radius: 12px; border: 1px solid var(--border); width: 320px; text-align: center; }
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div id="login-overlay">
        <div class="login-box">
            <h2 style="margin-bottom:20px; color:var(--accent);">AgileNet 登录</h2>
            <div style="display:flex; flex-direction:column; gap:12px;">
                <input type="text" id="username" placeholder="用户名" value="admin">
                <input type="password" id="password" placeholder="密码" value="admin123">
                <button onclick="doLogin()">登 录</button>
                <p id="login-err" style="color:var(--danger); font-size:0.85rem;" class="hidden"></p>
            </div>
        </div>
    </div>

    <div class="container">
        <header>
            <h1>⚡ AgileNet 控制台</h1>
            <div class="nav">
                <span id="user-info" style="align-self:center; color:var(--text-dim); margin-right:12px;"></span>
                <button onclick="doLogout()" class="btn-danger">退出登录</button>
            </div>
        </header>

        <!-- 节点管理 -->
        <div class="card">
            <div class="card-title">🌐 连入节点列表 (Relay Nodes)</div>
            <table>
                <thead>
                    <tr><th>节点 ID</th><th>节点名称</th><th>Status</th><th>最后上线</th><th>操作</th></tr>
                </thead>
                <tbody id="nodes-table-body">
                    <tr><td colspan="5" style="text-align:center; color:var(--text-dim);">加载中...</td></tr>
                </tbody>
            </table>
            <div class="form-group">
                <input type="text" id="new-node-name" placeholder="新节点名称 (e.g. node-hk-01)">
                <input type="text" id="new-node-token" placeholder="Node Auth Token">
                <button onclick="createNode()">添加节点</button>
            </div>
        </div>

        <!-- 代理路由规则管理 -->
        <div class="card">
            <div class="card-title">🔀 代理路由规则 (Proxy Routing Rules)</div>
            <table>
                <thead>
                    <tr><th>匹配模式 (Pattern)</th><th>模式类型</th><th>出站类型 (Outbound)</th><th>目标节点</th><th>操作</th></tr>
                </thead>
                <tbody id="routes-table-body">
                    <tr><td colspan="5" style="text-align:center; color:var(--text-dim);">加载中...</td></tr>
                </tbody>
            </table>
            <div class="form-group">
                <input type="text" id="new-route-pattern" placeholder="CIDR或域名 (e.g. 10.12.0.0/16)">
                <select id="new-route-ptype">
                    <option value="cidr">CIDR 网段</option>
                    <option value="exact_host">精确域名</option>
                    <option value="wildcard_host">通配符域名</option>
                </select>
                <select id="new-route-outbound">
                    <option value="direct">DIRECT (直连)</option>
                    <option value="tunnel">TUNNEL (隧道穿透)</option>
                </select>
                <input type="text" id="new-route-node" placeholder="目标节点名称 (选填)">
                <button onclick="createRoute()">添加规则</button>
            </div>
        </div>

        <!-- 权限组管理 -->
        <div class="card">
            <div class="card-title">🛡️ 权限组管理 (Permission Groups)</div>
            <table>
                <thead>
                    <tr><th>ID</th><th>组名称</th><th>备注说明</th><th>操作</th></tr>
                </thead>
                <tbody id="groups-table-body">
                    <tr><td colspan="4" style="text-align:center; color:var(--text-dim);">加载中...</td></tr>
                </tbody>
            </table>
            <div class="form-group">
                <input type="text" id="new-group-name" placeholder="权限组名称 (e.g. 开发组)">
                <input type="text" id="new-group-remark" placeholder="备注说明">
                <button onclick="createGroup()">添加权限组</button>
            </div>
        </div>

        <!-- 客户端账号管理 -->
        <div class="card">
            <div class="card-title">👥 客户端账号管理 (Client Accounts)</div>
            <table>
                <thead>
                    <tr><th>账号名称</th><th>所属权限组</th><th>状态</th><th>备注</th><th>操作</th></tr>
                </thead>
                <tbody id="accounts-table-body">
                    <tr><td colspan="5" style="text-align:center; color:var(--text-dim);">加载中...</td></tr>
                </tbody>
            </table>
            <div class="form-group">
                <input type="text" id="new-account-name" placeholder="客户端账号名 (e.g. zhangsan)">
                <input type="password" id="new-account-pass" placeholder="密码">
                <select id="new-account-group"></select>
                <input type="text" id="new-account-remark" placeholder="备注">
                <button onclick="createAccount()">添加账号</button>
            </div>
        </div>

        <!-- 审计日志 -->
        <div class="card">
            <div class="card-title">📜 系统审计日志 (Audit Logs)</div>
            <table>
                <thead>
                    <tr><th>操作人</th><th>动作 (Action)</th><th>操作目标</th><th>来源 IP</th><th>时间</th></tr>
                </thead>
                <tbody id="audit-table-body">
                    <tr><td colspan="5" style="text-align:center; color:var(--text-dim);">加载中...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const API_BASE = '/api/v1';

        function getToken() { return localStorage.getItem('agile_token'); }
        function setToken(t) { localStorage.setItem('agile_token', t); }
        function removeToken() { localStorage.removeItem('agile_token'); }

        async function fnFetch(url, options = {}) {
            options.headers = options.headers || {};
            const token = getToken();
            if (token) options.headers['Authorization'] = 'Bearer ' + token;
            if (options.body && typeof options.body === 'object') {
                options.headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(options.body);
            }
            const res = await fetch(API_BASE + url, options);
            if (res.status === 401) {
                showLogin();
                throw new Error('Unauthorized');
            }
            return res;
        }

        function showLogin() { document.getElementById('login-overlay').classList.remove('hidden'); }
        function hideLogin() { document.getElementById('login-overlay').classList.add('hidden'); }

        async function doLogin() {
            const u = document.getElementById('username').value;
            const p = document.getElementById('password').value;
            const errEl = document.getElementById('login-err');
            errEl.classList.add('hidden');
            try {
                const res = await fetch(API_BASE + '/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p })
                });
                if (!res.ok) throw new Error('用户名或密码错误');
                const data = await res.json();
                setToken(data.token);
                hideLogin();
                initApp();
            } catch (e) {
                errEl.innerText = e.message;
                errEl.classList.remove('hidden');
            }
        }

        function doLogout() {
            removeToken();
            showLogin();
        }

        async function initApp() {
            if (!getToken()) { showLogin(); return; }
            hideLogin();
            loadMe();
            loadNodes();
            loadRoutes();
            loadGroups();
            loadAccounts();
            loadAuditLogs();
        }

        async function loadMe() {
            try {
                const res = await fnFetch('/auth/me');
                const data = await res.json();
                document.getElementById('user-info').innerText = `👤 ${data.username} (${data.role})`;
            } catch(e){}
        }

        async function loadNodes() {
            const res = await fnFetch('/nodes');
            const data = await res.json();
            const tbody = document.getElementById('nodes-table-body');
            tbody.innerHTML = (data.nodes || []).map(n => `
                <tr>
                    <td><code>${n.id.substring(0,8)}...</code></td>
                    <td><b>${n.name}</b></td>
                    <td><span class="status-badge ${n.status === 'online' ? 'status-online' : 'status-offline'}">${n.status}</span></td>
                    <td>${n.last_seen || '从未上线'}</td>
                    <td><button onclick="deleteNode('${n.id}')" class="btn-danger">删除</button></td>
                </tr>
            `).join('') || '<tr><td colspan="5" style="text-align:center;">暂无节点</td></tr>';
        }

        async function createNode() {
            const name = document.getElementById('new-node-name').value;
            const token = document.getElementById('new-node-token').value;
            if (!name || !token) return alert('请填写节点名称与Token');
            await fnFetch('/nodes', { method: 'POST', body: { name, token } });
            document.getElementById('new-node-name').value = '';
            document.getElementById('new-node-token').value = '';
            loadNodes();
        }

        async function deleteNode(id) {
            if (!confirm('确定删除该节点？')) return;
            await fnFetch('/nodes/' + id, { method: 'DELETE' });
            loadNodes();
        }

        async function loadRoutes() {
            const res = await fnFetch('/routes');
            const data = await res.json();
            const tbody = document.getElementById('routes-table-body');
            tbody.innerHTML = (data.routes || []).map(r => `
                <tr>
                    <td><code>${r.pattern}</code></td>
                    <td>${r.pattern_type}</td>
                    <td><b style="color:${r.outbound_type==='tunnel'?'var(--accent)':'#a855f7'}">${r.outbound_type.toUpperCase()}</b></td>
                    <td>${r.node_id || '-'}</td>
                    <td><button onclick="deleteRoute('${r.id}')" class="btn-danger">删除</button></td>
                </tr>
            `).join('') || '<tr><td colspan="5" style="text-align:center;">暂无路由规则</td></tr>';
        }

        async function createRoute() {
            const pattern = document.getElementById('new-route-pattern').value;
            const pattern_type = document.getElementById('new-route-ptype').value;
            const outbound_type = document.getElementById('new-route-outbound').value;
            const node_id = document.getElementById('new-route-node').value || null;
            if (!pattern) return alert('请填写匹配模式');
            await fnFetch('/routes', { method: 'POST', body: { pattern, pattern_type, outbound_type, node_id } });
            document.getElementById('new-route-pattern').value = '';
            document.getElementById('new-route-node').value = '';
            loadRoutes();
        }

        async function deleteRoute(id) {
            if (!confirm('确定删除该路由？')) return;
            await fnFetch('/routes/' + id, { method: 'DELETE' });
            loadRoutes();
        }

        async function loadGroups() {
            const res = await fnFetch('/groups');
            const data = await res.json();
            const groups = data.groups || [];
            const tbody = document.getElementById('groups-table-body');
            tbody.innerHTML = groups.map(g => `
                <tr>
                    <td><code>${g.id.substring(0,8)}...</code></td>
                    <td><b>${g.name}</b></td>
                    <td>${g.remark || '-'}</td>
                    <td><button onclick="deleteGroup('${g.id}')" class="btn-danger">删除</button></td>
                </tr>
            `).join('') || '<tr><td colspan="4" style="text-align:center;">暂无权限组</td></tr>';

            const select = document.getElementById('new-account-group');
            select.innerHTML = groups.map(g => `<option value="${g.id}">${g.name}</option>`).join('');
        }

        async function createGroup() {
            const name = document.getElementById('new-group-name').value;
            const remark = document.getElementById('new-group-remark').value;
            if (!name) return alert('请填写权限组名称');
            await fnFetch('/groups', { method: 'POST', body: { name, remark } });
            document.getElementById('new-group-name').value = '';
            document.getElementById('new-group-remark').value = '';
            loadGroups();
        }

        async function deleteGroup(id) {
            if (!confirm('确定删除该权限组？')) return;
            await fnFetch('/groups/' + id, { method: 'DELETE' });
            loadGroups();
        }

        async function loadAccounts() {
            const res = await fnFetch('/accounts');
            const data = await res.json();
            const tbody = document.getElementById('accounts-table-body');
            tbody.innerHTML = (data.accounts || []).map(a => `
                <tr>
                    <td><b>${a.username}</b></td>
                    <td>${a.group_name || a.group_id}</td>
                    <td><span class="status-badge ${a.enabled ? 'status-online' : 'status-offline'}">${a.enabled ? '启用' : '禁用'}</span></td>
                    <td>${a.remark || '-'}</td>
                    <td><button onclick="deleteAccount('${a.id}')" class="btn-danger">删除</button></td>
                </tr>
            `).join('') || '<tr><td colspan="5" style="text-align:center;">暂无账号</td></tr>';
        }

        async function createAccount() {
            const username = document.getElementById('new-account-name').value;
            const password = document.getElementById('new-account-pass').value;
            const group_id = document.getElementById('new-account-group').value;
            const remark = document.getElementById('new-account-remark').value;
            if (!username || !password || !group_id) return alert('请填写完整账号、密码与选择权限组');
            await fnFetch('/accounts', { method: 'POST', body: { username, password, group_id, remark } });
            document.getElementById('new-account-name').value = '';
            document.getElementById('new-account-pass').value = '';
            document.getElementById('new-account-remark').value = '';
            loadAccounts();
        }

        async function deleteAccount(id) {
            if (!confirm('确定删除该账号？')) return;
            await fnFetch('/accounts/' + id, { method: 'DELETE' });
            loadAccounts();
        }

        async function loadAuditLogs() {
            const res = await fnFetch('/system/configs');
            const data = await res.json();
            const logs = data.audit_logs || [];
            const tbody = document.getElementById('audit-table-body');
            tbody.innerHTML = logs.map(l => `
                <tr>
                    <td><b>${l.operator}</b></td>
                    <td><code>${l.action}</code></td>
                    <td>${l.target}</td>
                    <td>${l.ip}</td>
                    <td>${l.created_at}</td>
                </tr>
            `).join('') || '<tr><td colspan="5" style="text-align:center;">暂无审计日志</td></tr>';
        }

        window.onload = initApp;
    </script>
</body>
</html>
"#;

pub async fn admin_page_handler() -> impl IntoResponse {
    Html(ADMIN_HTML)
}

pub fn create_ui_router() -> Router {
    Router::new()
        .route("/", get(admin_page_handler))
        .route("/admin", get(admin_page_handler))
}
