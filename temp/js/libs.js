// 动态库提取页逻辑
const libZipZone = document.getElementById('libZipZone');
const libZipInput = libZipZone.querySelector('input[type="file"]');
const libZipLabel = document.getElementById('libZipLabel');
libZipInput.addEventListener('change', () => {
    libZipLabel.textContent = libZipInput.files.length ? libZipInput.files[0].name : '';
});
libZipZone.addEventListener('dragover', e => { e.preventDefault(); libZipZone.classList.add('dragover'); });
libZipZone.addEventListener('dragleave', () => libZipZone.classList.remove('dragover'));
libZipZone.addEventListener('drop', e => {
    e.preventDefault();
    libZipZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        libZipInput.files = e.dataTransfer.files;
        libZipLabel.textContent = e.dataTransfer.files[0].name;
    }
});

function renderLibExtractResult(payload) {
    const items = payload.items || [];
    const html = items.map((item, idx) => {
        const postId = `lib-post-${idx}`;
        const xorId = `lib-xor-${idx}`;
        return `
        <div class="tool-result-card">
            <div class="tool-result-path">${esc(item.path || '')}</div>
            <div class="tool-result-grid">
                <div class="tool-result-item">
                    <div class="tool-result-label">POST_KEY</div>
                    <div class="tool-result-value" id="${postId}" data-raw="${encodeURIComponent(item.post_key || '')}">${esc(item.post_key || '')}</div>
                    <button class="copy-btn strategy-copy" onclick="copyCode('${postId}',this)">复制</button>
                </div>
                <div class="tool-result-item">
                    <div class="tool-result-label">XOR_KEY</div>
                    <div class="tool-result-value" id="${xorId}" data-raw="${encodeURIComponent(item.xor_key || '')}">${esc(item.xor_key || '')}</div>
                    <button class="copy-btn strategy-copy" onclick="copyCode('${xorId}',this)">复制</button>
                </div>
            </div>
        </div>`;
    }).join('');
    document.getElementById('libExtractResult').innerHTML = items.length
        ? `<div class="tool-result-list">${html}</div>`
        : `<div class="tool-result-card">没有提取到 libygsiyu.so</div>`;
}

document.getElementById('libExtractForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const btn = document.getElementById('libExtractBtn');
    const errEl = document.getElementById('libExtractError');
    const resultEl = document.getElementById('libExtractResult');
    btn.disabled = true;
    btn.textContent = '提取中...';
    errEl.classList.remove('show');
    resultEl.innerHTML = '';
    const file = libZipInput.files && libZipInput.files.length ? libZipInput.files[0] : null;
    try {
        if (!file) {
            throw new Error('请选择 lib.zip');
        }
        setUploadProgress('libExtractUploadProgress', 0, '准备上传动态库压缩包...');
        const uploaded = await uploadFileInChunks(file, 'extract_libs', (uploadedBytes, totalBytes) => {
            const percent = totalBytes ? (uploadedBytes / totalBytes) * 100 : 0;
            setUploadProgress('libExtractUploadProgress', percent, `上传 lib.zip ${percent.toFixed(1)}%`);
        });
        setUploadProgress('libExtractUploadProgress', 100, '上传完成，开始提取...');
        const data = await requestJson('/extract_libs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ libzip_token: uploaded.file_token }),
        });
        renderLibExtractResult(data);
        setUploadProgress('libExtractUploadProgress', 100, '动态库提取完成');
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.add('show');
        hideUploadProgress('libExtractUploadProgress');
    } finally {
        btn.disabled = false;
        btn.textContent = '提取动态库 Key';
    }
});
