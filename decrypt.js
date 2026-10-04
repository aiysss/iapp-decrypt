// 解密页逻辑
let autoExtractEnabled = false;
let cacheEnabled = true; // 默认开启缓存命中
let autoExtractFiles = {
    libso: null,
    nativeSo: null,
};
let lastDecryptResult = null;

function showAutoExtractModal() {
    document.getElementById('modalOverlay').style.display = 'flex';
}

function closeAutoExtractModal() {
    document.getElementById('modalOverlay').style.display = 'none';
}

function confirmAutoExtract() {
    const toggle = document.getElementById('autoExtractToggle');
    const apkZone = document.getElementById('apkZone');
    const manualFields = document.getElementById('manualFields');
    const fileZone = document.getElementById('fileZone');
    const label = toggle.querySelector('.label');
    
    autoExtractEnabled = !autoExtractEnabled;
    toggle.classList.toggle('active');
    
    if (autoExtractEnabled) {
        label.textContent = '手动输入';
        apkZone.style.display = 'block';
        manualFields.style.opacity = '0.5';
        manualFields.style.pointerEvents = 'none';
        fileZone.style.display = 'none';
        document.querySelectorAll('#manualFields input[required]').forEach(input => {
            input.removeAttribute('required');
        });
        // 密码是用户私密输入，自动提取填不了，保持可编辑
        const pwdKeyInput = document.querySelector('input[name="pwd_key"]');
        if (pwdKeyInput) {
            const pwdField = pwdKeyInput.closest('.field');
            if (pwdField) pwdField.style.opacity = '1';
            pwdKeyInput.style.pointerEvents = 'auto';
        }
    } else {
        label.textContent = '自动提取';
        apkZone.style.display = 'none';
        manualFields.style.opacity = '1';
        manualFields.style.pointerEvents = 'auto';
        fileZone.style.display = 'block';
        document.querySelectorAll('#manualFields input[data-original-required]').forEach(input => {
            input.setAttribute('required', '');
        });
    }
    
    closeAutoExtractModal();
}

function handleAutoExtractClick() {
    const toggle = document.getElementById('autoExtractToggle');
    if (toggle.classList.contains('active')) {
        confirmAutoExtract();
    } else {
        showAutoExtractModal();
    }
}

function handleCacheToggleClick() {
    const toggle = document.getElementById('cacheToggle');
    cacheEnabled = !cacheEnabled;
    toggle.classList.toggle('active');
}

function renderResult(data) {
    lastDecryptResult = data;
    const files = data.files || {};
    const fileCount = Object.keys(files).length;
    const failedCount = (data.failed || []).length;
    const isOk = data.ok;
    const strategy = data.strategy || {};
    const cacheHit = !!data.cache_hit;
    const hintText = cacheHit
        ? (data.cache_message || '成功命中缓存，已直接返回历史解密结果')
        : '如需再次解密，请刷新页面';

    let cardsHtml = '';
    for (const [filename, content] of Object.entries(files)) {
        const isEntry = filename === data.entry_file;
        const safeId = 'code-' + filename.replace(/[^a-zA-Z0-9]/g, '_');
        cardsHtml += `
        <div class="card">
            <div class="card-head">
                <div class="card-name">
                    <span class="dot ${isEntry ? 'entry' : 'normal'}"></span>
                    <span title="${esc(filename)}">${esc(filename)}</span>
                    ${isEntry ? '<span class="badge">ENTRY</span>' : ''}
                </div>
                <button class="copy-btn" onclick="copyCode('${safeId}',this)">复制</button>
            </div>
            <div class="card-body">
                <div class="code-wrap">
                    <pre class="code-block" id="${safeId}" data-raw="${encodeURIComponent(content)}">${esc(content)}</pre>
                </div>
            </div>
        </div>`;
    }

    let failedHtml = '';
    if (failedCount > 0) {
        const items = data.failed.map(f =>
            `<li><span class="fname">${esc(f.name || '')}</span><span class="err">${esc(f.error || '')}</span></li>`
        ).join('');
        failedHtml = `
        <div class="failed-section">
            <div class="head">⚠ 失败的文件 (${failedCount})</div>
            <ul>${items}</ul>
        </div>`;
    }

    let strategyHtml = '';
    if (isOk && Object.keys(strategy).length) {
        const strategyItems = [
            ['CANDIDATE', strategy.candidate],
            ['POST_KEY', strategy.post_key_hex],
            ['XOR_KEY', strategy.xor_key_hex],
            ['SIGN_KEY', strategy.sign_key],
            ['SIGN_INPUT', strategy.sign_input],
            ['SIGNATURE_USED', strategy.signature_used ? '是' : '否'],
        ].filter(([, value]) => value !== undefined && value !== null && value !== '');

        const itemHtml = strategyItems.map(([label, value]) => {
            const strValue = String(value);
            const safeId = 'strategy-' + label.replace(/[^a-zA-Z0-9]/g, '_');
            return `
            <div class="strategy-item wide">
                <div class="strategy-label">${esc(label)}</div>
                <div class="strategy-value" id="${safeId}" data-raw="${encodeURIComponent(strValue)}">${esc(strValue)}</div>
                <button class="copy-btn strategy-copy" onclick="copyCode('${safeId}',this)">复制</button>
            </div>`;
        }).join('');
        strategyHtml = `
        <div class="strategy-panel">
            <div class="strategy-title">Key</div>
            <div class="strategy-grid">${itemHtml}</div>
        </div>`;
    }

    document.getElementById('resultWrap').innerHTML = `
        <div class="top-bar">
            <h2><span class="dot ${isOk ? '' : 'fail'}"></span>解密结果</h2>
            <div class="top-actions">
                <span class="pill ${isOk ? 'pill-ok' : 'pill-fail'}">${isOk ? '✓ 成功' : '✗ 失败'}</span>
                ${cacheHit ? '<span class="pill pill-ok">缓存命中</span>' : ''}
                ${isOk && fileCount ? '<button class="copy-btn" onclick="downloadResultZip()">导出 ZIP</button>' : ''}
            </div>
        </div>
        <div class="hint-bar">${esc(hintText)}</div>
        <div class="info-bar">
            <div class="info-chip">
                <span class="num green">${fileCount}</span>
                <span class="desc">已解密<br>文件</span>
            </div>
            <div class="info-chip">
                <span class="num ${failedCount > 0 ? 'red' : 'orange'}">${failedCount}</span>
                <span class="desc">失败<br>文件</span>
            </div>
            <div class="info-chip">
                <span class="num accent">${esc(data.entry_file || '-')}</span>
                <span class="desc">入口<br>文件</span>
            </div>
        </div>
        ${strategyHtml}
        <div class="cards">${cardsHtml || '<div style="grid-column:1/-1;text-align:center;padding:60px;color:var(--text3)">无文件数据</div>'}</div>
        ${failedHtml}
    `;

    document.getElementById('formWrap').classList.add('hidden');
    document.getElementById('resultWrap').classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function fillFormFields(data) {
    if (!data) return;
    const fields = [
        ['package_name', 'package_name'],
        ['version_name', 'version_name'],
        ['version_code', 'version_code'],
        ['app_name', 'app_name'],
        ['sok', 'sok'],
        ['dek', 'dek'],
        ['sign_key', 'sign_key'],
        ['sign_b64', 'sign_b64'],
        ['post_key', 'post_key'],
        ['xor_key', 'xor_key'],
    ];
    fields.forEach(([dataKey, fieldName]) => {
        const input = document.querySelector(`input[name="${fieldName}"]`);
        if (input && data[dataKey] && data[dataKey] !== 'N/A') {
            input.value = data[dataKey];
        }
    });
    
    // 如果有提取到lib.so文件，自动填充到上传区域
    if (data.lib_so_base64) {
        const fileZone = document.getElementById('fileZone');
        const fileInput = fileZone.querySelector('input[type="file"]');
        const fileLabel = document.getElementById('fileLabel');
        
        // 将base64转换为Blob
        const byteString = atob(data.lib_so_base64);
        const mimeType = 'application/octet-stream';
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        for (let i = 0; i < byteString.length; i++) {
            ia[i] = byteString.charCodeAt(i);
        }
        const blob = new Blob([ab], { type: mimeType });
        
        // 创建File对象
        const file = new File([blob], data.lib_so_name || 'lib.so', { type: mimeType });
        autoExtractFiles.libso = file;
        
        // 创建DataTransfer对象来设置文件
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        fileInput.files = dataTransfer.files;
        fileLabel.textContent = file.name;
        
        // 显示文件上传区域
        fileZone.style.display = 'block';
    }

    if (data.native_so_base64) {
        const byteString = atob(data.native_so_base64);
        const mimeType = 'application/octet-stream';
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        for (let i = 0; i < byteString.length; i++) {
            ia[i] = byteString.charCodeAt(i);
        }
        const blob = new Blob([ab], { type: mimeType });
        autoExtractFiles.nativeSo = new File(
            [blob],
            data.native_so_name || 'libygsiyu.so',
            { type: mimeType }
        );
    } else {
        autoExtractFiles.nativeSo = null;
    }

    applyManualModeUI(inferDetectedMode(data));
}

function inferDetectedMode(data) {
    const detected = String((data && data.detected_mode) || '').trim().toLowerCase();
    if (detected === 'legacy4') return 'legacy4';
    const sok = String((data && data.sok) || '').trim();
    return sok && sok.length <= 4 ? 'legacy4' : 'current';
}

function applyManualModeUI(mode) {
    const select = document.getElementById('packageMode');
    const hint = document.getElementById('packageModeHint');
    const postKeyRow = document.getElementById('postKeyRow');
    const legacySignRow = document.getElementById('legacySignRow');
    const signB64Row = document.getElementById('signB64Row');
    const postKeyInput = document.querySelector('input[name="post_key"]');
    const xorKeyInput = document.querySelector('input[name="xor_key"]');
    const signKeyInput = document.querySelector('input[name="sign_key"]');
    const pwdKeyInput = document.querySelector('input[name="pwd_key"]');
    const signB64Input = document.querySelector('input[name="sign_b64"]');
    const sokInput = document.querySelector('input[name="sok"]');
    if (!select || !hint || !postKeyRow || !legacySignRow || !postKeyInput || !xorKeyInput || !signKeyInput || !pwdKeyInput || !sokInput) return;

    const legacy4 = mode === 'legacy4';
    select.value = legacy4 ? 'legacy4' : 'current';
    postKeyRow.style.display = legacy4 ? 'none' : 'grid';
    legacySignRow.style.display = legacy4 ? 'grid' : 'none';
    // signB64Row 含 pwd_key（通用）+ sign_b64（current），始终显示
    if (signB64Row) signB64Row.style.display = 'grid';
    postKeyInput.disabled = legacy4;
    xorKeyInput.disabled = legacy4;
    signKeyInput.disabled = !legacy4;
    if (signB64Input) signB64Input.disabled = legacy4;

    if (legacy4) {
        postKeyInput.value = '';
        xorKeyInput.value = '';
        sokInput.placeholder = '4位so密钥，如 9ecc';
        hint.textContent = '选择版本只影响手动输入参数；自动提取始终按参数自动判断版本。';
        return;
    }

    sokInput.placeholder = 'so密钥';
    hint.textContent = '选择版本只影响手动输入参数；自动提取始终按参数自动判断版本。';
}

const fileZone = document.getElementById('fileZone');
const fileInput = fileZone.querySelector('input[type="file"]');
const fileLabel = document.getElementById('fileLabel');
fileInput.addEventListener('change', () => {
    fileLabel.textContent = fileInput.files.length ? fileInput.files[0].name : '';
});
fileZone.addEventListener('dragover', e => { e.preventDefault(); fileZone.classList.add('dragover'); });
fileZone.addEventListener('dragleave', () => fileZone.classList.remove('dragover'));
fileZone.addEventListener('drop', e => {
    e.preventDefault();
    fileZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        fileLabel.textContent = e.dataTransfer.files[0].name;
    }
});

const apkZone = document.getElementById('apkZone');
const apkInput = apkZone.querySelector('input[type="file"]');
const apkLabel = document.getElementById('apkLabel');
const packageModeSelect = document.getElementById('packageMode');
packageModeSelect.addEventListener('change', () => applyManualModeUI(packageModeSelect.value));
applyManualModeUI(packageModeSelect.value);
apkInput.addEventListener('change', handleApkUpload);
apkZone.addEventListener('dragover', e => { e.preventDefault(); apkZone.classList.add('dragover'); });
apkZone.addEventListener('dragleave', () => apkZone.classList.remove('dragover'));
apkZone.addEventListener('drop', e => {
    e.preventDefault();
    apkZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        apkInput.files = e.dataTransfer.files;
        handleApkUpload();
    }
});

async function handleApkUpload() {
    if (!apkInput.files.length) return;
    
    const file = apkInput.files[0];
    const manualFields = document.getElementById('manualFields');
    apkLabel.textContent = file.name;

    const originalBtnText = document.getElementById('submitBtn').textContent;
    const submitBtn = document.getElementById('submitBtn');
    const errEl = document.getElementById('errorMsg');
    submitBtn.disabled = true;
    submitBtn.textContent = '提取参数中...';
    errEl.classList.remove('show');
    setUploadProgress('apkExtractProgress', 0, '准备上传 APK...');

    try {
        const uploaded = await uploadFileInChunks(file, 'extract_apk', (uploadedBytes, totalBytes) => {
            const percent = totalBytes ? (uploadedBytes / totalBytes) * 100 : 0;
            setUploadProgress('apkExtractProgress', percent, `上传 APK ${percent.toFixed(1)}%`);
        });
        setUploadProgress('apkExtractProgress', 100, '上传完成，开始提取参数...');
        const data = await requestJson('/extract_apk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ apk_token: uploaded.file_token }),
        });
        if (data.ok && data.data) {
            fillFormFields(data.data);
            manualFields.style.opacity = '1';
            manualFields.style.pointerEvents = 'auto';
            setUploadProgress('apkExtractProgress', 100, '参数提取完成');
            showToast('参数提取成功，可手动修改后解密');
        }
    } catch (err) {
        errEl.textContent = '提取参数失败: ' + err.message;
        errEl.classList.add('show');
        hideUploadProgress('apkExtractProgress');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalBtnText;
    }
}

async function lookupDecryptCache(file) {
    if (!file || !window.crypto || !crypto.subtle) {
        return null;
    }
    try {
        const libSha256 = await sha256HexOfFile(file);
        const resp = await fetch('/cache_lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ lib_sha256: libSha256 }),
        });
        if (!resp.ok) {
            return null;
        }
        const data = await resp.json();
        return data && data.cache_hit ? data : null;
    } catch (_) {
        return null;
    }
}

function buildDecryptPayload(form, fileTokens) {
    const payload = {};
    const fields = form.querySelectorAll('input, select, textarea');
    for (const field of fields) {
        const name = field.name;
        if (!name || field.disabled || name === 'apk') {
            continue;
        }
        if (field.type === 'file') {
            continue;
        }
        payload[name] = field.value ?? '';
    }
    payload.mode = autoExtractEnabled ? 'auto' : packageModeSelect.value;
    payload.libso_token = fileTokens.libso;
    if (fileTokens.nativeSo) {
        payload.native_so_token = fileTokens.nativeSo;
    }
    return payload;
}

function downloadResultZip() {
    if (!lastDecryptResult || !lastDecryptResult.files || !Object.keys(lastDecryptResult.files).length) {
        showToast('暂无可导出的文件');
        return;
    }
    const files = Object.entries(lastDecryptResult.files).map(([name, content]) => ({
        name,
        content: String(content ?? ''),
    }));
    const zipBlob = buildStoredZip(files);
    const zipName = sanitizeZipName(lastDecryptResult.entry_file || 'decrypt_result') + '.zip';
    const url = URL.createObjectURL(zipBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = zipName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('已导出 ZIP');
}

document.getElementById('decryptForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const btn = document.getElementById('submitBtn');
    const errEl = document.getElementById('errorMsg');
    btn.disabled = true;
    btn.textContent = '检查缓存中...';
    errEl.classList.remove('show');

    try {
        const libFile = fileInput.files && fileInput.files.length ? fileInput.files[0] : null;
        if (!libFile) {
            throw new Error('请选择 lib.so');
        }
        if (cacheEnabled) {
            const cached = await lookupDecryptCache(libFile);
            if (cached) {
                renderResult(cached);
                showToast('成功命中缓存，已直接返回结果');
                hideUploadProgress('decryptUploadProgress');
                return;
            }
        }

        const totalUploadBytes = libFile.size + (autoExtractEnabled && autoExtractFiles.nativeSo ? autoExtractFiles.nativeSo.size : 0);
        let uploadOffset = 0;
        btn.textContent = '上传文件中...';
        setUploadProgress('decryptUploadProgress', 0, '准备上传解密文件...');
        const libUpload = await uploadFileInChunks(libFile, 'decrypt_libso', (uploadedBytes, totalBytes) => {
            const percent = totalUploadBytes ? ((uploadOffset + uploadedBytes) / totalUploadBytes) * 100 : 0;
            setUploadProgress('decryptUploadProgress', percent, `上传 lib.so ${percent.toFixed(1)}%`);
        });
        uploadOffset += libFile.size;

        let nativeSoToken = '';
        if (autoExtractEnabled && autoExtractFiles.nativeSo) {
            const nativeFile = autoExtractFiles.nativeSo;
            const uploadedNative = await uploadFileInChunks(nativeFile, 'decrypt_native_so', (uploadedBytes) => {
                const percent = totalUploadBytes ? ((uploadOffset + uploadedBytes) / totalUploadBytes) * 100 : 0;
                setUploadProgress('decryptUploadProgress', percent, `上传 native.so ${percent.toFixed(1)}%`);
            });
            nativeSoToken = uploadedNative.file_token;
        }
        setUploadProgress('decryptUploadProgress', 100, '上传完成，开始解密...');
        btn.textContent = '解密中...';
        const payload = buildDecryptPayload(this, {
            libso: libUpload.file_token,
            nativeSo: nativeSoToken,
        });
        const data = await requestJson('/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        renderResult(data);
        setUploadProgress('decryptUploadProgress', 100, '解密请求已完成');
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.add('show');
        hideUploadProgress('decryptUploadProgress');
    } finally {
        btn.disabled = false;
        btn.textContent = '解密';
    }
});

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#manualFields input[required]').forEach(input => {
        input.setAttribute('data-original-required', '');
    });
});
