// 公共工具函数（上传/压缩/复制/toast 等）
function switchTab(btn, name) {
    const container = btn.parentElement;
    container.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    moveTabIndicator(container, btn);
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
}

function moveTabIndicator(container, activeBtn) {
    const indicator = container.querySelector('.tab-indicator');
    if (!indicator) return;
    indicator.style.left = activeBtn.offsetLeft + 'px';
    indicator.style.width = activeBtn.offsetWidth + 'px';
}

function initTabIndicators() {
    document.querySelectorAll('.code-tabs').forEach(container => {
        const activeBtn = container.querySelector('.tab-btn.active');
        if (activeBtn) moveTabIndicator(container, activeBtn);
    });
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

const zipCrcTable = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c >>> 0;
    }
    return table;
})();

function crc32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
        crc = zipCrcTable[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function dosDateTime(date) {
    const year = Math.max(1980, date.getFullYear());
    const dosTime = ((date.getHours() & 31) << 11)
        | ((date.getMinutes() & 63) << 5)
        | ((Math.floor(date.getSeconds() / 2)) & 31);
    const dosDate = (((year - 1980) & 127) << 9)
        | (((date.getMonth() + 1) & 15) << 5)
        | (date.getDate() & 31);
    return { dosTime, dosDate };
}

function writeUint16(view, offset, value) {
    view.setUint16(offset, value & 0xFFFF, true);
}

function writeUint32(view, offset, value) {
    view.setUint32(offset, value >>> 0, true);
}

function buildStoredZip(files) {
    const encoder = new TextEncoder();
    const now = new Date();
    const { dosTime, dosDate } = dosDateTime(now);
    const localParts = [];
    const centralParts = [];
    let offset = 0;

    files.forEach(file => {
        const nameBytes = encoder.encode(file.name);
        const dataBytes = encoder.encode(file.content);
        const crc = crc32(dataBytes);

        const localHeader = new Uint8Array(30 + nameBytes.length);
        const localView = new DataView(localHeader.buffer);
        writeUint32(localView, 0, 0x04034b50);
        writeUint16(localView, 4, 20);
        writeUint16(localView, 6, 0);
        writeUint16(localView, 8, 0);
        writeUint16(localView, 10, dosTime);
        writeUint16(localView, 12, dosDate);
        writeUint32(localView, 14, crc);
        writeUint32(localView, 18, dataBytes.length);
        writeUint32(localView, 22, dataBytes.length);
        writeUint16(localView, 26, nameBytes.length);
        writeUint16(localView, 28, 0);
        localHeader.set(nameBytes, 30);
        localParts.push(localHeader, dataBytes);

        const centralHeader = new Uint8Array(46 + nameBytes.length);
        const centralView = new DataView(centralHeader.buffer);
        writeUint32(centralView, 0, 0x02014b50);
        writeUint16(centralView, 4, 20);
        writeUint16(centralView, 6, 20);
        writeUint16(centralView, 8, 0);
        writeUint16(centralView, 10, 0);
        writeUint16(centralView, 12, dosTime);
        writeUint16(centralView, 14, dosDate);
        writeUint32(centralView, 16, crc);
        writeUint32(centralView, 20, dataBytes.length);
        writeUint32(centralView, 24, dataBytes.length);
        writeUint16(centralView, 28, nameBytes.length);
        writeUint16(centralView, 30, 0);
        writeUint16(centralView, 32, 0);
        writeUint16(centralView, 34, 0);
        writeUint16(centralView, 36, 0);
        writeUint32(centralView, 38, 0);
        writeUint32(centralView, 42, offset);
        centralHeader.set(nameBytes, 46);
        centralParts.push(centralHeader);

        offset += localHeader.length + dataBytes.length;
    });

    const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
    const endRecord = new Uint8Array(22);
    const endView = new DataView(endRecord.buffer);
    writeUint32(endView, 0, 0x06054b50);
    writeUint16(endView, 4, 0);
    writeUint16(endView, 6, 0);
    writeUint16(endView, 8, files.length);
    writeUint16(endView, 10, files.length);
    writeUint32(endView, 12, centralSize);
    writeUint32(endView, 16, offset);
    writeUint16(endView, 20, 0);

    return new Blob([...localParts, ...centralParts, endRecord], { type: 'application/zip' });
}

function sanitizeZipName(name) {
    return (name || 'decrypt_result')
        .replace(/[\\/:*?"<>|]+/g, '_')
        .replace(/\s+/g, '_')
        .replace(/^_+|_+$/g, '') || 'decrypt_result';
}

function copyCode(id, btn) {
    const el = document.getElementById(id);
    if (!el) return;
    const text = decodeURIComponent(el.dataset.raw);
    const done = () => {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓ 已复制';
        btn.classList.add('copied');
        const t = document.getElementById('toast');
        t.classList.add('show');
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.classList.remove('copied');
            t.classList.remove('show');
        }, 1800);
    };
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(done).catch(() => {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            done();
        });
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        done();
    }
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
}

async function requestJson(url, options = {}) {
    const resp = await fetch(url, options);
    let data = null;
    try {
        data = await resp.json();
    } catch (_) {
        if (!resp.ok) {
            throw new Error('HTTP ' + resp.status);
        }
        return {};
    }
    if (!resp.ok || (data && data.ok === false)) {
        throw new Error((data && data.error) || ('HTTP ' + resp.status));
    }
    return data;
}

function setUploadProgress(id, percent, text) {
    const root = document.getElementById(id);
    if (!root) return;
    const fill = root.querySelector('.upload-progress-fill');
    const label = root.querySelector('.upload-progress-text');
    const safePercent = Math.max(0, Math.min(100, Number(percent) || 0));
    root.classList.add('show');
    fill.style.width = safePercent.toFixed(1) + '%';
    label.textContent = text || ('上传进度 ' + Math.round(safePercent) + '%');
}

function hideUploadProgress(id) {
    const root = document.getElementById(id);
    if (!root) return;
    root.classList.remove('show');
    const fill = root.querySelector('.upload-progress-fill');
    const label = root.querySelector('.upload-progress-text');
    fill.style.width = '0%';
    label.textContent = '上传进度 0%';
}

function uploadChunk(uploadId, index, blob, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', `/upload_chunk?upload_id=${encodeURIComponent(uploadId)}&index=${index}`);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.upload.onprogress = (event) => {
            if (onProgress && event.lengthComputable) {
                onProgress(event.loaded);
            }
        };
        xhr.onload = () => {
            let payload = {};
            try {
                payload = JSON.parse(xhr.responseText || '{}');
            } catch (_) {}
            if (xhr.status >= 200 && xhr.status < 300 && payload.ok !== false) {
                resolve(payload);
                return;
            }
            reject(new Error(payload.error || ('HTTP ' + xhr.status)));
        };
        xhr.onerror = () => reject(new Error('网络异常，分片上传失败'));
        xhr.send(blob);
    });
}

async function uploadFileInChunks(file, purpose, onProgress) {
    const initData = await requestJson('/upload_init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: file.name,
            size: file.size,
            purpose: purpose || '',
        }),
    });
    const uploadId = initData.upload_id;
    const chunkSize = initData.chunk_size || (2 * 1024 * 1024);
    let uploaded = 0;
    let index = 0;
    while (uploaded < file.size) {
        const end = Math.min(uploaded + chunkSize, file.size);
        const chunk = file.slice(uploaded, end);
        await uploadChunk(uploadId, index, chunk, (loaded) => {
            if (onProgress) {
                onProgress(uploaded + loaded, file.size, file.name);
            }
        });
        uploaded = end;
        index += 1;
        if (onProgress) {
            onProgress(uploaded, file.size, file.name);
        }
    }
    return await requestJson('/upload_complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ upload_id: uploadId }),
    });
}

async function sha256HexOfFile(file) {
    const buffer = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Tab 指示器：页面加载时定位到当前激活 Tab；窗口尺寸变化时重新计算
initTabIndicators();
window.addEventListener('resize', () => {
    document.querySelectorAll('.code-tabs').forEach(container => {
        const activeBtn = container.querySelector('.tab-btn.active');
        if (activeBtn) moveTabIndicator(container, activeBtn);
    });
});
