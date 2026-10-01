// 动态加密修复页逻辑
let lastRepairResult = null;

const repairDexZone = document.getElementById('repairDexZone');
const repairDexInput = repairDexZone.querySelector('input[type="file"]');
const repairDexLabel = document.getElementById('repairDexLabel');
repairDexInput.addEventListener('change', () => {
    repairDexLabel.textContent = repairDexInput.files.length ? repairDexInput.files[0].name : '';
});
repairDexZone.addEventListener('dragover', e => { e.preventDefault(); repairDexZone.classList.add('dragover'); });
repairDexZone.addEventListener('dragleave', () => repairDexZone.classList.remove('dragover'));
repairDexZone.addEventListener('drop', e => {
    e.preventDefault();
    repairDexZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        repairDexInput.files = e.dataTransfer.files;
        repairDexLabel.textContent = e.dataTransfer.files[0].name;
    }
});

const repairSrcZipZone = document.getElementById('repairSrcZipZone');
const repairSrcZipInput = repairSrcZipZone.querySelector('input[type="file"]');
const repairSrcZipLabel = document.getElementById('repairSrcZipLabel');
repairSrcZipInput.addEventListener('change', () => {
    repairSrcZipLabel.textContent = repairSrcZipInput.files.length ? repairSrcZipInput.files[0].name : '';
});
repairSrcZipZone.addEventListener('dragover', e => { e.preventDefault(); repairSrcZipZone.classList.add('dragover'); });
repairSrcZipZone.addEventListener('dragleave', () => repairSrcZipZone.classList.remove('dragover'));
repairSrcZipZone.addEventListener('drop', e => {
    e.preventDefault();
    repairSrcZipZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        repairSrcZipInput.files = e.dataTransfer.files;
        repairSrcZipLabel.textContent = e.dataTransfer.files[0].name;
    }
});

function downloadRepairZip() {
    if (!lastRepairResult || !lastRepairResult.download_url) {
        showToast('暂无可下载的修复 ZIP');
        return;
    }
    const a = document.createElement('a');
    a.href = lastRepairResult.download_url;
    a.download = lastRepairResult.zip_name || 'repaired_source.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
}

function renderRepairResult(payload) {
    lastRepairResult = payload;
    const modifiedFiles = payload.modified_files || [];
    const dictPreview = payload.dict_preview || [];

    const modifiedHtml = modifiedFiles.length
        ? modifiedFiles.map(item => `
            <div class="tool-result-card">
                <div class="tool-result-path">${esc(item.path || '')}</div>
                <div class="api-desc">修复次数: ${esc(String(item.replaced || 0))}</div>
            </div>
        `).join('')
        : '<div class="tool-result-card">没有匹配到需要修复的源码调用，已原样打包返回。</div>';

    const dictHtml = dictPreview.length
        ? dictPreview.map(item => `
            <div class="tool-result-item">
                <div class="tool-result-label">${esc(item.from || '')}</div>
                <div class="tool-result-value">${esc(item.to || '')}</div>
            </div>
        `).join('')
        : '<div class="tool-result-card">没有可展示的映射预览</div>';

    document.getElementById('repairResult').innerHTML = `
        <div class="tool-result-card">
            <div class="top-bar" style="margin-bottom:12px;">
                <h2><span class="dot"></span>动态加密修复结果</h2>
                <div class="top-actions">
                    <span class="pill pill-ok">✓ 成功</span>
                    <button class="copy-btn" onclick="downloadRepairZip()">导出 ZIP</button>
                </div>
            </div>
            <div class="info-bar">
                <div class="info-chip">
                    <span class="num green">${esc(String(payload.dex_count || 0))}</span>
                    <span class="desc">扫描<br>Dex</span>
                </div>
                <div class="info-chip">
                    <span class="num green">${esc(String(payload.mapping_count || 0))}</span>
                    <span class="desc">映射<br>数量</span>
                </div>
                <div class="info-chip">
                    <span class="num orange">${esc(String(payload.modified_file_count || 0))}</span>
                    <span class="desc">修复<br>文件</span>
                </div>
                <div class="info-chip">
                    <span class="num accent">${esc(String(payload.replaced_count || 0))}</span>
                    <span class="desc">替换<br>次数</span>
                </div>
            </div>
            <div class="hint-bar">${esc(payload.message || '动态加密修复成功')}</div>
        </div>
        <div class="api-section">
            <h3>映射预览</h3>
            <div class="tool-result-grid">${dictHtml}</div>
        </div>
        <div class="api-section">
            <h3>修复文件</h3>
            <div class="tool-result-list">${modifiedHtml}</div>
        </div>
    `;
}

document.getElementById('repairForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const btn = document.getElementById('repairBtn');
    const errEl = document.getElementById('repairError');
    const resultEl = document.getElementById('repairResult');
    btn.disabled = true;
    btn.textContent = '修复中...';
    errEl.classList.remove('show');
    resultEl.innerHTML = '';
    const dexFile = repairDexInput.files && repairDexInput.files.length ? repairDexInput.files[0] : null;
    const srcFile = repairSrcZipInput.files && repairSrcZipInput.files.length ? repairSrcZipInput.files[0] : null;
    try {
        if (!dexFile) {
            throw new Error('请选择 dex.zip / apk');
        }
        if (!srcFile) {
            throw new Error('请选择源码 zip');
        }
        const totalUploadBytes = dexFile.size + srcFile.size;
        setUploadProgress('repairUploadProgress', 0, '准备上传修复文件...');
        const dexUploaded = await uploadFileInChunks(dexFile, 'repair_dynamic_dexzip', (uploadedBytes) => {
            const percent = totalUploadBytes ? (uploadedBytes / totalUploadBytes) * 100 : 0;
            setUploadProgress('repairUploadProgress', percent, `上传 Dex 包 ${percent.toFixed(1)}%`);
        });
        const srcUploaded = await uploadFileInChunks(srcFile, 'repair_dynamic_srczip', (uploadedBytes) => {
            const percent = totalUploadBytes ? ((dexFile.size + uploadedBytes) / totalUploadBytes) * 100 : 0;
            setUploadProgress('repairUploadProgress', percent, `上传源码包 ${percent.toFixed(1)}%`);
        });
        setUploadProgress('repairUploadProgress', 100, '上传完成，开始修复...');
        const data = await requestJson('/repair_dynamic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                dexzip_token: dexUploaded.file_token,
                srczip_token: srcUploaded.file_token,
            }),
        });
        renderRepairResult(data);
        setUploadProgress('repairUploadProgress', 100, '源码修复完成');
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.add('show');
        hideUploadProgress('repairUploadProgress');
    } finally {
        btn.disabled = false;
        btn.textContent = '开始修复源码';
    }
});
