// 文档站配置与逻辑（依赖 common.js 的 uploadFileInChunks / showToast，md.js 的 renderMarkdown / escapeHtml）

// ===== 页面配置 =====
const DOCS_GROUPS = [
    {
        title: '开始使用',
        pages: [
            { id: 'overview', title: 'API 介绍', file: 'docs/overview.md' },
            { id: 'upload', title: '分片上传', file: 'docs/upload.md', debug: {
                mode: 'upload',
                purposes: ['decrypt_libso', 'extract_apk', 'extract_libs', 'repair_dynamic_dexzip', 'repair_dynamic_srczip', 'decrypt_native_so'],
            } },
        ],
    },
    {
        title: 'API 接口',
        pages: [
            { id: 'decrypt', title: '解密源码', file: 'docs/decrypt.md', debug: {
                method: 'POST', path: '/decrypt',
                files: [
                    { name: 'libso', label: 'lib.so（加密源码）', purpose: 'decrypt_libso', required: true },
                    { name: 'native_so', label: 'native.so（可选）', purpose: 'decrypt_native_so', required: false },
                ],
                fields: [
                    { name: 'package_name', label: 'package_name（包名）', required: true },
                    { name: 'version_name', label: 'version_name（版本名）', required: true },
                    { name: 'version_code', label: 'version_code（版本号）', required: true },
                    { name: 'app_name', label: 'app_name（应用名）', required: true },
                    { name: 'dek', label: 'dek（dex 密钥）', required: true },
                    { name: 'sok', label: 'sok（可选）' },
                    { name: 'mode', label: 'mode', type: 'select', options: ['auto', 'current', 'legacy', 'legacy4'], default: 'auto' },
                    { name: 'format', label: 'format', type: 'select', options: ['json', 'text'], default: 'json' },
                ],
            } },
            { id: 'extract-apk', title: '提取 APK 参数', file: 'docs/extract-apk.md', debug: {
                method: 'POST', path: '/extract_apk',
                files: [{ name: 'apk', label: 'APK 文件', purpose: 'extract_apk', required: true }],
                fields: [],
            } },
            { id: 'extract-libs', title: '提取动态库 Key', file: 'docs/extract-libs.md', debug: {
                method: 'POST', path: '/extract_libs',
                files: [{ name: 'libzip', label: 'lib.zip（含 libygsiyu.so）', purpose: 'extract_libs', required: true }],
                fields: [],
            } },
            { id: 'repair', title: '动态加密修复', file: 'docs/repair.md', debug: {
                method: 'POST', path: '/repair_dynamic',
                files: [
                    { name: 'dexzip', label: 'dex 包（zip/apk）', purpose: 'repair_dynamic_dexzip', required: true },
                    { name: 'srczip', label: '待修复源码 zip', purpose: 'repair_dynamic_srczip', required: true },
                ],
                fields: [],
            } },
            { id: 'cache', title: '缓存查询', file: 'docs/cache.md', debug: {
                method: 'POST', path: '/cache_lookup',
                files: [],
                fields: [{ name: 'lib_sha256', label: 'lib_sha256（64 位 hex）', required: true }],
            } },
        ],
    },
    {
        title: '其他',
        pages: [
            { id: 'download', title: '下载修复结果', file: 'docs/download.md', debug: {
                method: 'GET', path: '/repair_download', responseType: 'file',
                files: [],
                fields: [{ name: 'token', label: 'token（32 位 hex）', required: true }],
            } },
            { id: 'health', title: '健康检查', file: 'docs/health.md', debug: {
                method: 'GET', path: '/health', responseType: 'json',
                files: [], fields: [],
            } },
        ],
    },
];

const DOCS_FLAT = [];
DOCS_GROUPS.forEach((g) => g.pages.forEach((p) => DOCS_FLAT.push(Object.assign({ group: g.title }, p))));

// ===== 导航 =====
function currentPageId() {
    const m = location.hash.match(/^#\/([\w-]+)/);
    return m ? m[1] : 'overview';
}
function pageById(id) {
    return DOCS_FLAT.find((p) => p.id === id) || DOCS_FLAT[0];
}
function pageIndex(id) {
    return DOCS_FLAT.findIndex((p) => p.id === id);
}

// ===== 侧边栏 =====
function renderSidebar() {
    const el = document.getElementById('docsSidebar');
    const active = currentPageId();
    let html = '';
    DOCS_GROUPS.forEach((g) => {
        html += '<div class="docs-group">';
        html += '<div class="docs-group-title">' + escapeHtml(g.title) + '</div>';
        g.pages.forEach((p) => {
            const cls = p.id === active ? 'docs-side-item active' : 'docs-side-item';
            html += '<a class="' + cls + '" href="#/' + p.id + '">' + escapeHtml(p.title) + '</a>';
        });
        html += '</div>';
    });
    el.innerHTML = html;
}

// ===== 翻页 =====
function renderPrevNext() {
    const el = document.getElementById('docsNav');
    const idx = pageIndex(currentPageId());
    const prev = idx > 0 ? DOCS_FLAT[idx - 1] : null;
    const next = idx < DOCS_FLAT.length - 1 ? DOCS_FLAT[idx + 1] : null;
    let html = '';
    if (prev) {
        html += '<a class="docs-nav-card" href="#/' + prev.id + '">'
            + '<span class="docs-nav-dir">← 上一页</span>'
            + '<span class="docs-nav-title">' + escapeHtml(prev.title) + '</span></a>';
    } else {
        html += '<span></span>';
    }
    if (next) {
        html += '<a class="docs-nav-card docs-nav-next" href="#/' + next.id + '">'
            + '<span class="docs-nav-dir">下一页 →</span>'
            + '<span class="docs-nav-title">' + escapeHtml(next.title) + '</span></a>';
    }
    el.innerHTML = html;
}

// ===== 正文 =====
async function renderPage() {
    const page = pageById(currentPageId());
    renderSidebar();
    renderPrevNext();
    document.title = page.title + ' - iApp Decrypt 文档';

    const content = document.getElementById('mdContent');
    content.innerHTML = '<p>加载中...</p>';
    try {
        const md = await fetch(page.file).then((r) => r.text());
        content.innerHTML = renderMarkdown(md);
    } catch (err) {
        content.innerHTML = '<p>文档加载失败: ' + escapeHtml(err.message) + '</p>';
    }

    renderDebugger(page.debug);
    window.scrollTo(0, 0);
}

// ===== 在线调试 =====
let currentDebug = null;

function renderDebugger(debug) {
    currentDebug = debug;
    const section = document.getElementById('debugSection');
    if (!debug) { section.innerHTML = ''; return; }

    let html = '<div class="debug-box"><div class="debug-title">在线调试</div>';

    if (debug.mode === 'upload') {
        html += '<div class="debug-form">'
            + '<div class="debug-field"><label>选择文件</label><input type="file" id="dbgFile"></div>'
            + '<div class="debug-field"><label>purpose</label><select id="dbgPurpose">'
            + debug.purposes.map((p) => '<option value="' + p + '">' + p + '</option>').join('')
            + '</select></div>'
            + '<button class="debug-send" onclick="sendUploadDebug()">上传并获取 token</button>'
            + '</div>';
    } else {
        let formHtml = '';
        (debug.files || []).forEach((f) => {
            formHtml += '<div class="debug-field"><label>' + escapeHtml(f.label) + (f.required ? ' <b>*</b>' : '') + '</label>'
                + '<input type="file" data-file="' + f.name + '" data-purpose="' + f.purpose + '"></div>';
        });
        (debug.fields || []).forEach((f) => {
            if (f.type === 'select') {
                formHtml += '<div class="debug-field"><label>' + escapeHtml(f.label) + (f.required ? ' <b>*</b>' : '') + '</label>'
                    + '<select data-field="' + f.name + '">'
                    + f.options.map((o) => '<option' + (o === f.default ? ' selected' : '') + '>' + o + '</option>').join('')
                    + '</select></div>';
            } else {
                formHtml += '<div class="debug-field"><label>' + escapeHtml(f.label) + (f.required ? ' <b>*</b>' : '') + '</label>'
                    + '<input type="text" data-field="' + f.name + '"'
                    + (f.default ? ' value="' + escapeHtml(f.default) + '"' : '') + '></div>';
            }
        });
        html += '<div class="debug-form">' + formHtml
            + '<button class="debug-send" onclick="sendDebugRequest()">发送请求</button>'
            + '</div>';
    }

    html += '<div class="debug-result" id="debugResult"></div></div>';
    section.innerHTML = html;
}

function debugResultHtml(text) {
    return '<pre>' + escapeHtml(text) + '</pre>';
}
function debugErrorHtml(msg) {
    return '<div class="debug-err">' + escapeHtml(msg) + '</div>';
}

async function sendUploadDebug() {
    const fileInput = document.getElementById('dbgFile');
    const purpose = document.getElementById('dbgPurpose').value;
    const result = document.getElementById('debugResult');
    const file = fileInput.files && fileInput.files[0];
    if (!file) { result.innerHTML = debugErrorHtml('请先选择文件'); return; }
    result.innerHTML = '<p>上传中...</p>';
    try {
        const uploaded = await uploadFileInChunks(file, purpose, (loaded, total) => {
            result.innerHTML = '<p>上传中 ' + Math.round(loaded / total * 100) + '%</p>';
        });
        result.innerHTML = debugResultHtml(JSON.stringify(uploaded, null, 2));
    } catch (err) {
        result.innerHTML = debugErrorHtml(err.message);
    }
}

async function sendDebugRequest() {
    const debug = currentDebug;
    if (!debug) return;
    const result = document.getElementById('debugResult');
    const box = document.querySelector('.debug-form');

    // 收集文本字段
    const body = {};
    let missing = null;
    (debug.fields || []).forEach((f) => {
        const input = box.querySelector('[data-field="' + f.name + '"]');
        const val = input ? input.value.trim() : '';
        if (f.required && !val) missing = missing || f.label;
        if (val) body[f.name] = val;
    });
    if (missing) { result.innerHTML = debugErrorHtml('缺少必填字段: ' + missing); return; }

    try {
        // 上传文件，换取 token
        const fileInputs = box.querySelectorAll('[data-file]');
        for (const input of fileInputs) {
            const name = input.getAttribute('data-file');
            const purpose = input.getAttribute('data-purpose');
            const required = (debug.files || []).find((f) => f.name === name).required;
            const file = input.files && input.files[0];
            if (required && !file) { result.innerHTML = debugErrorHtml('请先选择文件: ' + name); return; }
            if (file) {
                result.innerHTML = '<p>上传 ' + name + ' ...</p>';
                const uploaded = await uploadFileInChunks(file, purpose);
                body[name + '_token'] = uploaded.file_token;
            }
        }
    } catch (err) {
        result.innerHTML = debugErrorHtml('上传失败: ' + err.message);
        return;
    }

    result.innerHTML = '<p>请求中...</p>';
    try {
        let resp;
        if (debug.method === 'GET') {
            const qs = (debug.fields || []).map((f) => encodeURIComponent(f.name) + '=' + encodeURIComponent(body[f.name] || '')).join('&');
            const url = debug.path + (qs ? '?' + qs : '');
            if (debug.responseType === 'file') {
                // 文件下载：直接跳转
                result.innerHTML = '<p>正在下载...</p><a class="debug-link" href="' + url + '" download>点击下载结果</a>';
                return;
            }
            resp = await fetch(url);
        } else {
            resp = await fetch(debug.path, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
        }
        const text = await resp.text();
        let out = text;
        try { out = JSON.stringify(JSON.parse(text), null, 2); } catch (_) { /* 非 JSON 保持原文 */ }
        result.innerHTML = debugResultHtml(out);
    } catch (err) {
        result.innerHTML = debugErrorHtml('请求失败: ' + err.message);
    }
}

// ===== 移动端侧边栏开关 =====
function toggleSidebar(open) {
    document.getElementById('docsSidebar').classList.toggle('open', open);
    document.getElementById('docsBackdrop').classList.toggle('show', open);
}

// ===== 初始化 =====
window.addEventListener('hashchange', function () {
    toggleSidebar(false);
    renderPage();
});
document.getElementById('docsMenuBtn').addEventListener('click', function () { toggleSidebar(true); });
document.getElementById('docsBackdrop').addEventListener('click', function () { toggleSidebar(false); });
document.getElementById('docsSidebar').addEventListener('click', function (e) {
    if (e.target.closest('.docs-side-item')) toggleSidebar(false);
});
renderSidebar();
renderPage();
