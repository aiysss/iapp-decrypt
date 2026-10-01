// 极简 Markdown 渲染器：仅覆盖 api.md 用到的子集
// 标题 / 代码块 / 行内代码 / 表格 / 无序列表 / 有序列表 / 粗体 / 链接 / 引用 / 分隔线 / 段落
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function inlineMd(text) {
    // 先按行内代码切分，代码内部不再解析其他格式
    const parts = String(text).split(/(`[^`]+`)/g);
    let out = '';
    for (const p of parts) {
        if (p.length > 2 && p.startsWith('`') && p.endsWith('`')) {
            out += '<code>' + escapeHtml(p.slice(1, -1)) + '</code>';
        } else {
            let t = escapeHtml(p);
            t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
            out += t;
        }
    }
    return out;
}

function splitTableRow(line) {
    let s = line.trim();
    if (s.startsWith('|')) s = s.slice(1);
    if (s.endsWith('|')) s = s.slice(0, -1);
    return s.split('|').map((c) => c.trim());
}

function isTableSeparator(line) {
    return /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/.test(line);
}

function renderMarkdown(md) {
    const lines = String(md).replace(/\r\n/g, '\n').split('\n');
    let html = '';
    let i = 0;
    let para = [];

    const flushPara = () => {
        if (para.length) {
            html += '<p>' + inlineMd(para.join(' ')) + '</p>\n';
            para = [];
        }
    };

    while (i < lines.length) {
        const line = lines[i];

        // 围栏代码块
        const fence = line.match(/^```(\w*)\s*$/);
        if (fence) {
            flushPara();
            const lang = fence[1] ? ' class="language-' + escapeHtml(fence[1]) + '"' : '';
            const code = [];
            i++;
            while (i < lines.length && !/^```\s*$/.test(lines[i])) {
                code.push(lines[i]);
                i++;
            }
            i++; // 跳过收尾 ```
            html += '<pre><code' + lang + '>' + escapeHtml(code.join('\n')) + '</code></pre>\n';
            continue;
        }

        // 表格（表头行 + 分隔行）
        if (line.trim().startsWith('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
            flushPara();
            const header = splitTableRow(line);
            i += 2; // 跳过表头与分隔行
            html += '<table><thead><tr>' + header.map((h) => '<th>' + inlineMd(h) + '</th>').join('') + '</tr></thead><tbody>\n';
            while (i < lines.length && lines[i].trim().startsWith('|')) {
                const cells = splitTableRow(lines[i]);
                html += '<tr>' + cells.map((c) => '<td>' + inlineMd(c) + '</td>').join('') + '</tr>\n';
                i++;
            }
            html += '</tbody></table>\n';
            continue;
        }

        // 标题
        const h = line.match(/^(#{1,6})\s+(.*)$/);
        if (h) {
            flushPara();
            const level = h[1].length;
            html += '<h' + level + '>' + inlineMd(h[2]) + '</h' + level + '>\n';
            i++;
            continue;
        }

        // 分隔线
        if (/^\s*([-*_])\s*(\1\s*){2,}$/.test(line)) {
            flushPara();
            html += '<hr>\n';
            i++;
            continue;
        }

        // 无序列表
        if (/^\s*[-*]\s+/.test(line)) {
            flushPara();
            html += '<ul>\n';
            while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
                html += '<li>' + inlineMd(lines[i].replace(/^\s*[-*]\s+/, '')) + '</li>\n';
                i++;
            }
            html += '</ul>\n';
            continue;
        }

        // 有序列表
        if (/^\s*\d+\.\s+/.test(line)) {
            flushPara();
            html += '<ol>\n';
            while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
                html += '<li>' + inlineMd(lines[i].replace(/^\s*\d+\.\s+/, '')) + '</li>\n';
                i++;
            }
            html += '</ol>\n';
            continue;
        }

        // 引用
        if (/^\s*>\s?/.test(line)) {
            flushPara();
            const quote = [];
            while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
                quote.push(lines[i].replace(/^\s*>\s?/, ''));
                i++;
            }
            html += '<blockquote>' + quote.map(inlineMd).join('<br>') + '</blockquote>\n';
            continue;
        }

        // 空行
        if (line.trim() === '') {
            flushPara();
            i++;
            continue;
        }

        // 普通段落
        para.push(line.trim());
        i++;
    }
    flushPara();
    return html;
}
