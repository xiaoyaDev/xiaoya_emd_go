let logRefreshTimer = null;
let currentPage = 1;

function showStatus(message, isError = false) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = `status ${isError ? 'error' : 'success'}`;
    status.style.display = 'block';
    setTimeout(() => status.style.display = 'none', 3000);
}
// 初始化主题
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || ''; // 默认亮色（空字符串）
    document.body.dataset.theme = savedTheme;
}
// 切换主题
function toggleTheme() {
    const body = document.body;
    body.dataset.theme = body.dataset.theme === 'dark' ? '' : 'dark';
    localStorage.setItem('theme', body.dataset.theme); // 保存主题
}

document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', function() {
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        this.classList.add('active');
        document.getElementById(this.dataset.tab + '-tab').classList.add('active');
        if (this.dataset.tab === 'logs') {
            debouncedRefreshLogs();
        } else if (this.dataset.tab === 'config') {
            loadConfigPage();
        } else if (this.dataset.tab === 'main') {
            loadPaths(); // 刷新路径列表和按钮状态
            getSyncStatus(); // 刷新同步状态
        }
        if (logRefreshTimer && this.dataset.tab !== 'logs') {
            clearTimeout(logRefreshTimer);
            logRefreshTimer = null;
        }
    });
});

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, options);
        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
        return await response.json();
    } catch (error) {
        showStatus(`请求失败: ${error.message}`, true);
        throw error;
    }
}

async function getLogs(limit) {
    return await fetchAPI(`/api/logs?limit=${limit}`);
}

function debounce(fn, delay) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn(...args), delay);
    };
}
const debouncedLoadPaths = debounce(loadPaths, 1000);
async function refreshLogs() {
    const limit = parseInt(document.getElementById('logLimit').value);
    const filter = document.getElementById('logFilter').value;
    const search = document.getElementById('logSearch').value;
    const url = `/api/logs?limit=${limit}&page=${currentPage}&filter=${filter}&search=${encodeURIComponent(search)}`;
    const logContainer = document.getElementById('logContainer');
    
    try {
        const data = await fetchAPI(url);
        logContainer.innerHTML = ''; // 清空现有内容
        if (data.total === 0) {
            logContainer.innerHTML = '<div class="log-entry">暂无日志</div>';
        } else {
            data.logs.forEach(log => {
                logContainer.innerHTML += `
                    <div class="log-entry">
                        <div class="log-timestamp">${log.timestamp}</div>
                        <div class="log-type log-type-${log.type}">${log.type.toUpperCase()}</div>
                        <div class="log-message">${log.message}</div>
                    </div>`;
            });
        }
        // 确保在 DOM 更新后滚动到顶部，显示最新日志
        requestAnimationFrame(() => {
            logContainer.scrollTop = 0;
        });

        const totalPages = Math.ceil(data.total / limit) || 1;
        // 确保 currentPage 在有效范围内
        if (currentPage < 1) currentPage = 1;
        if (currentPage > totalPages) currentPage = totalPages;
        
        document.getElementById('pageInfo').textContent = `第 ${currentPage} 页 / 共 ${totalPages} 页 (总计 ${data.total} 条)`;
        document.getElementById('logMemoryInfo').textContent = `最大条目数: ${data.logBufferSize} 条，预计内存占用: ${data.estimatedMemory}`;
        document.getElementById('prevPage').disabled = currentPage === 1;
        document.getElementById('nextPage').disabled = currentPage >= totalPages;

        // 更新跳转页下拉菜单
        const jumpPageSelect = document.getElementById('jumpPage');
        jumpPageSelect.innerHTML = '';
        for (let i = 1; i <= totalPages; i++) {
            const option = document.createElement('option');
            option.value = i;
            option.textContent = `第 ${i} 页`;
            if (i === currentPage) {
                option.selected = true;
            }
            jumpPageSelect.appendChild(option);
        }

        const interval = parseInt(document.getElementById('logRefreshInterval').value);
        if (interval > 0 && document.querySelector('.tab-button[data-tab="logs"]').classList.contains('active')) {
            if (logRefreshTimer) clearTimeout(logRefreshTimer);
            logRefreshTimer = setTimeout(refreshLogs, interval);
        }
    } catch (error) {
        logContainer.innerHTML = '<div class="log-entry">加载日志失败，请检查服务器状态</div>';
        showStatus(`加载日志失败: ${error.message}`, true);
    }
}

const debouncedRefreshLogs = debounce(refreshLogs, 500);

function updateLogRefresh() {
    if (logRefreshTimer) {
        clearTimeout(logRefreshTimer);
        logRefreshTimer = null;
    }
    const interval = parseInt(document.getElementById('logRefreshInterval').value);
    if (interval > 0 && document.querySelector('.tab-button[data-tab="logs"]').classList.contains('active')) {
        refreshLogs();
        logRefreshTimer = setTimeout(refreshLogs, interval);
    } else {
        console.log("切换到手动刷新，停止自动刷新");
    }
}

function changePage(delta) {
    const limit = parseInt(document.getElementById('logLimit').value);
    const total = parseInt(document.getElementById('pageInfo').textContent.match(/总计 (\d+) 条/)[1]);
    const totalPages = Math.ceil(total / limit) || 1;
    currentPage += delta;
    if (currentPage < 1) currentPage = 1;
    if (currentPage > totalPages) currentPage = totalPages;
    debouncedRefreshLogs();
}

function jumpToPage() {
    const jumpPageSelect = document.getElementById('jumpPage');
    const jumpPage = parseInt(jumpPageSelect.value);
    const limit = parseInt(document.getElementById('logLimit').value);
    const total = parseInt(document.getElementById('pageInfo').textContent.match(/总计 (\d+) 条/)[1] || 0);
    const totalPages = Math.ceil(total / limit) || 1;

    if (!isNaN(jumpPage) && jumpPage >= 1 && jumpPage <= totalPages) {
        currentPage = jumpPage;
        debouncedRefreshLogs();
    } else {
        // 如果页码无效，重置为当前页
        jumpPageSelect.value = currentPage;
        showStatus('无效的页码', true);
    }
}

async function exportLogs() {
    try {
        const response = await fetch('/api/logs?action=export');
        const data = await response.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `logs_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
        a.click();
        window.URL.revokeObjectURL(url);
        showStatus('日志导出成功');
    } catch (error) {
        showStatus(`导出失败: ${error.message}`, true);
    }
}

async function clearLogs() {
    if (!confirm('确定要清空所有日志吗？此操作不可恢复。')) return;
    try {
        await fetchAPI('/api/logs?action=clear');
        showStatus('日志已清空');
        debouncedRefreshLogs();
    } catch (error) {
        showStatus(`清空失败: ${error.message}`, true);
    }
}

async function getSyncStatus() {
    try {
        const status = await fetchAPI('/api/sync');
        const config = await fetchAPI('/api/config/get');
        const runningStatus = document.getElementById('syncRunningStatus');
        const message = document.getElementById('syncMessage');
        const nextRun = document.getElementById('syncNextRun');
        const intervalDisplay = document.getElementById('syncIntervalDisplay');
        const intervalInput = document.getElementById('syncInterval');
        const localTimestamp = document.getElementById('localTimestamp');
        const startBtn = document.getElementById('startSyncBtn');
        const stopBtn = document.getElementById('stopSyncBtn');
        runningStatus.textContent = status.isRunning ? '运行中' : '已停止';
        runningStatus.className = status.isRunning ? 'sync-running' : 'sync-waiting';
        message.textContent = status.message;
        nextRun.textContent = status.nextRun || '-';
        intervalDisplay.textContent = status.interval ? `${status.interval} 小时` : '-';
        if (!intervalInput.dataset.initialized) {
            intervalInput.placeholder = status.interval ? `${status.interval}小时` : '小时';
            intervalInput.dataset.initialized = 'true';
        }
        localTimestamp.textContent = config.scanListTime ? new Date(config.scanListTime).toLocaleString() : '未知';
        startBtn.disabled = status.isRunning;
        stopBtn.disabled = !status.isRunning;
    } catch (error) {
        showStatus(`获取同步状态失败: ${error.message}`, true);
    }
}

async function startSync() {
    try {
        await fetchAPI('/api/sync/start', { method: 'POST' });
        showStatus('同步已开始');
        getSyncStatus();
        if (document.querySelector('.tab-button[data-tab="logs"]').classList.contains('active')) {
            setTimeout(debouncedRefreshLogs, 1000);
        }
    } catch (error) {
        showStatus(`启动失败: ${error.message}`, true);
    }
}

async function stopSync() {
    try {
        const response = await fetchAPI('/api/sync/stop', { method: 'POST' });
        getSyncStatus();
        await loadPaths(); // 刷新按钮状态
        if (document.querySelector('.tab-button[data-tab="logs"]').classList.contains('active')) {
            setTimeout(debouncedRefreshLogs, 1000);
        }
    } catch (error) {
        showStatus(`停止失败: ${error.message}`, true);
    }
}
async function loadPaths() {
    try {
        const { allPaths, activePaths, pathUpdateNotices } = await fetchAPI('/api/paths');
        const pathCountsResponse = await fetchAPI('/api/paths/count');
        const pathCounts = pathCountsResponse.counts;
        const pathCountsMessage = pathCountsResponse.message;
        const serverCounts = await fetchAPI('/api/server-paths-count');
        const pathList = document.getElementById('pathList');
        pathList.innerHTML = allPaths.length ? '' : '<div class="checkbox-group">暂无目录</div>';
        if (pathCountsMessage) {
            pathList.innerHTML += `<div class="path-count-message">${pathCountsMessage}</div>`;
        }
        allPaths.forEach(path => {
            const localCount = pathCounts[path] >= 0 ? pathCounts[path] : '请手动刷新本地数据...';
            const serverCount = serverCounts[path] >= 0 ? serverCounts[path] : '未知';
            const diff = localCount !== '请手动刷新本地数据...' && serverCount !== '未知' ? localCount - serverCount : null;
            let diffText = '';
            let diffClass = '';
            if (diff !== null) {
                if (diff > 0) {
                    diffText = `(多${diff}个)`;
                    diffClass = 'file-count-ahead';
                } else if (diff < 0) {
                    diffText = `(少${-diff}个)`;
                    diffClass = 'file-count-behind';
                } else {
                    diffText = '(一致)';
                    diffClass = 'file-count-equal';
                }
            }
            const hasUpdate = pathUpdateNotices && pathUpdateNotices[path] ? '<span class="update-notice">有可更新数据!</span>' : '';

            pathList.innerHTML += `
                <div class="checkbox-group">
                    <input type="checkbox" id="path_${path}" ${activePaths.includes(path) ? 'checked' : ''}>
                    <label for="path_${path}">${path}</label>
                    <span class="file-count ${diffClass}" data-diff="${diff !== null ? diff : '未知'}">(本地: ${localCount}, 服务器: ${serverCount}) ${diffText}</span>
                    ${hasUpdate}
                </div>`;
        });
    } catch (error) {
        await loadRecycleBinCount();
        showStatus(`加载路径失败: ${error.message}`, true);
    }
}

async function savePaths() {
    const activePaths = Array.from(document.querySelectorAll('#pathList input:checked'))
        .map(cb => cb.id.replace('path_', ''));
    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ activePaths })
        });
        showStatus(`同步目录已保存 (${activePaths.length} 个)`);
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
    }
}

async function saveInterval() {
    const interval = parseInt(document.getElementById('syncInterval').value);
    if (isNaN(interval) || interval < 1 || interval > 24) {
        showStatus('同步间隔必须为 1-24 的整数', true);
        return;
    }
    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interval })
        });
        showStatus(`同步间隔已设置为 ${interval} 小时`);
        getSyncStatus();
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
    }
}

async function refreshLocalData() {
    try {
        console.log("触发刷新本地数据");
        await fetchAPI('/api/refresh-local', { method: 'POST' });
        showStatus("本地文件数据库已刷新");
        await loadPaths(); // 刷新路径列表
        console.log("本地数据刷新完成");
    } catch (error) {
        showStatus(`刷新失败: ${error.message}`, true);
        console.error(`刷新本地数据失败: ${error.message}`);
    }
}

async function loadServers() {
    try {
        const servers = await fetchAPI('/api/servers');
        document.getElementById('serverList').value = servers.join('\n');
    } catch (error) {
        showStatus(`加载服务器列表失败: ${error.message}`, true);
    }
}

async function saveLogSize() {
    const logSize = parseInt(document.getElementById('logSizeInput').value);
    if (isNaN(logSize) || logSize < 1) {
        showStatus('最大条目数必须为正整数', true);
        return;
    }
    try {
        const response = await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logSize })
        });
        showStatus(`最大日志条目数已设置为 ${response.logSize} 条`);
        debouncedRefreshLogs();
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
    }
}

async function loadConfigPage() {
    await loadServers();
    await loadDNSConfig();
    await loadBandwidthConfig();
    await loadConcurrencyConfig();
    await loadMemoryConfig();
}

async function loadDNSConfig() {
    try {
        const config = await fetchAPI('/api/config/get');
        document.getElementById('dnsEnabled').checked = config.dnsEnabled;
        document.getElementById('dnsType').value = config.dnsType || 'doh';
        document.getElementById('dnsServer').value = config.dnsServer || '1.1.1.1';
    } catch (error) {
        showStatus(`加载 DNS 配置失败: ${error.message}`, true);
    }
}

async function toggleDNSEnabled() {
    const dnsEnabled = document.getElementById('dnsEnabled').checked;
    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dnsEnabled })
        });
        showStatus(`自定义 DNS 已${dnsEnabled ? '启用' : '关闭'}`);
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
        document.getElementById('dnsEnabled').checked = !dnsEnabled;
    }
}

async function saveDNSConfig() {
    const dnsEnabled = document.getElementById('dnsEnabled').checked;
    const dnsType = document.getElementById('dnsType').value;
    const dnsServer = document.getElementById('dnsServer').value.trim();

    if (dnsEnabled) {
        if (!dnsServer) {
            showStatus('DNS 服务器地址不能为空', true);
            return;
        }
        if (dnsType === 'doh') {
            if (!dnsServer.match(/^https?:\/\//) && !dnsServer.includes('/dns-query')) {
                showStatus('DoH 服务器需以 http:// 或 https:// 开头，或包含 /dns-query', true);
                return;
            }
        } else if (dnsType === 'dot') {
            if (!dnsServer.match(/^[\w.-]+(:[0-9]+)?$/)) {
                showStatus('DoT 服务器需为有效域名或 IP 地址，可选端口号（如 :853）', true);
                return;
            }
        }
    }

    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dnsType, dnsServer, dnsEnabled })
        });
        showStatus(`DNS 配置已保存 (${dnsEnabled ? `${dnsType.toUpperCase()}: ${dnsServer}` : '系统默认'})`);
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
    }
}

async function loadBandwidthConfig() {
    try {
        const config = await fetchAPI('/api/config/get');
        document.getElementById('bandwidthLimitEnabled').checked = config.bandwidthLimitEnabled || false;
        document.getElementById('bandwidthLimitMBps').value = config.bandwidthLimitMBps || 5.0;
    } catch (error) {
        showStatus(`加载带宽配置失败: ${error.message}`, true);
    }
}

async function toggleBandwidthLimitEnabled() {
    const checkbox = document.getElementById('bandwidthLimitEnabled');
    const bandwidthLimitEnabled = checkbox.checked;
    const bandwidthLimitMBpsInput = document.getElementById('bandwidthLimitMBps');
    let bandwidthLimitMBps = parseFloat(bandwidthLimitMBpsInput.value);

    if (isNaN(bandwidthLimitMBps) || bandwidthLimitMBps <= 0) {
        bandwidthLimitMBps = 5.0;
    }

    if (bandwidthLimitEnabled && bandwidthLimitMBps <= 0) {
        showStatus('带宽限制值必须为正数', true);
        checkbox.checked = !bandwidthLimitEnabled;
        return;
    }

    try {
        const response = await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                bandwidthLimitEnabled, 
                bandwidthLimitMBps 
            })
        });
        showStatus(`带宽限制已${bandwidthLimitEnabled ? '启用' : '关闭'}`);
    } catch (error) {
        showStatus(`保存带宽限制失败: ${error.message}`, true);
        checkbox.checked = !bandwidthLimitEnabled;
    }
}

async function saveBandwidthConfig() {
    const checkbox = document.getElementById('bandwidthLimitEnabled');
    const bandwidthLimitEnabled = checkbox.checked;
    const bandwidthLimitMBpsInput = document.getElementById('bandwidthLimitMBps');
    let bandwidthLimitMBps = parseFloat(bandwidthLimitMBpsInput.value);

    if (isNaN(bandwidthLimitMBps) || bandwidthLimitMBps <= 0) {
        bandwidthLimitMBps = 5.0;
    }

    if (bandwidthLimitEnabled && bandwidthLimitMBps <= 0) {
        showStatus('带宽限制必须为正数', true);
        return;
    }

    try {
        const response = await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                bandwidthLimitEnabled, 
                bandwidthLimitMBps 
            })
        });
        showStatus(`带宽限制已保存: ${bandwidthLimitEnabled ? `${bandwidthLimitMBps} MB/s` : '关闭'}`);
    } catch (error) {
        showStatus(`保存带宽限制失败: ${error.message}`, true);
    }
}

async function loadConcurrencyConfig() {
    try {
        const config = await fetchAPI('/api/config/get');
        document.getElementById('maxConcurrency').value = config.maxConcurrency || 500;
    } catch (error) {
        showStatus(`加载并发配置失败: ${error.message}`, true);
    }
}

async function saveConcurrencyConfig() {
    const maxConcurrency = parseInt(document.getElementById('maxConcurrency').value);
    if (isNaN(maxConcurrency) || maxConcurrency < 1) {
        showStatus('最大并发数必须为正整数', true);
        return;
    }
    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ maxConcurrency })
        });
        showStatus(`最大并发数已设置为 ${maxConcurrency}`);
    } catch (error) {
        showStatus(`保存失败: ${error.message}`, true);
    }
}
//加载回收站数量
async function loadRecycleBinCount() {
    try {
        const data = await fetchAPI('/api/recycle-bin/count');
        document.getElementById('recycleBinCount').textContent = data.fileCount;
    } catch (error) {
        document.getElementById('recycleBinCount').textContent = '未知';
        showStatus(`加载回收站文件数量失败: ${error.message}`, true);
    }
}
async function resetScanListTime() {
    try {
        const response = await fetchAPI('/api/reset-scanlist-time', { method: 'POST' });
        showStatus(response.message);
        getSyncStatus(); // 刷新同步状态，更新 localTimestamp
        if (document.querySelector('.tab-button[data-tab="logs"]').classList.contains('active')) {
            setTimeout(debouncedRefreshLogs, 1000);
        }
    } catch (error) {
        showStatus(`重置数据包时间失败: ${error.message}`, true);
    }
}
async function exportRecycleBinList() {
    try {
        const response = await fetch('/api/recycle-bin/list');
        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
        const text = await response.text();
        if (text === "回收站为空") {
            showStatus('回收站为空，无文件可导出');
            return;
        }
        const blob = new Blob([text], { type: 'text/plain; charset=utf-8' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `recycle_bin_tree_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
        a.click();
        window.URL.revokeObjectURL(url);
        showStatus('回收站文件列表导出成功');
    } catch (error) {
        showStatus(`导出失败: ${error.message}`, true);
    }
}
async function clearRecycleBin() {
    try {
        const data = await fetchAPI('/api/recycle-bin/count');
        const fileCount = data.fileCount;
        if (fileCount === 0) {
            showStatus('回收站为空，无需清空');
            return;
        }
        if (!confirm(`此次清空文件数量为 ${fileCount}，是否确定清除？`)) {
            return;
        }
        const response = await fetchAPI('/api/recycle-bin/clear', { method: 'POST' });
        showStatus(response.message);
        await loadRecycleBinCount();
    } catch (error) {
        showStatus(`清空回收站失败: ${error.message}`, true);
    }
}

// 加载内存限制配置
async function loadMemoryConfig() {
    try {
        const config = await fetchAPI('/api/config/get');
        document.getElementById('memoryLimitEnabled').checked = config.memoryLimitEnabled || false;
        document.getElementById('memoryLimitMB').value = config.memoryLimitMB || 512;
    } catch (error) {
        showStatus(`加载内存配置失败: ${error.message}`, true);
    }
}

// 切换内存限制开关
async function toggleMemoryLimitEnabled() {
    const checkbox = document.getElementById('memoryLimitEnabled');
    const memoryLimitEnabled = checkbox.checked;
    const memoryLimitMBInput = document.getElementById('memoryLimitMB');
    let memoryLimitMB = parseFloat(memoryLimitMBInput.value);

    if (isNaN(memoryLimitMB) || memoryLimitMB <= 0) {
        memoryLimitMB = 512;
    }

    if (memoryLimitEnabled && memoryLimitMB <= 0) {
        showStatus('内存限制值必须为正数', true);
        checkbox.checked = false;
        return;
    }

    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ memoryLimitEnabled, memoryLimitMB })
        });
        showStatus(`内存限制已${memoryLimitEnabled ? '启用' : '关闭'}`);
    } catch (error) {
        showStatus(`保存内存限制失败: ${error.message}`, true);
        checkbox.checked = !memoryLimitEnabled;
    }
}

// 保存内存限制配置
async function saveMemoryConfig() {
    const checkbox = document.getElementById('memoryLimitEnabled');
    const memoryLimitEnabled = checkbox.checked;
    const memoryLimitMBInput = document.getElementById('memoryLimitMB');
    let memoryLimitMB = parseFloat(memoryLimitMBInput.value);

    if (isNaN(memoryLimitMB) || memoryLimitMB <= 0) {
        memoryLimitMB = 512;
    }

    if (memoryLimitEnabled && memoryLimitMB <= 0) {
        showStatus('内存限制值必须为正数', true);
        return;
    }

    try {
        await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ memoryLimitEnabled, memoryLimitMB })
        });
        showStatus(`内存限制已保存: ${memoryLimitEnabled ? `${memoryLimitMB} MB` : '关闭'}`);
    } catch (error) {
        showStatus(`保存内存限制失败: ${error.message}`, true);
    }
}

// 加载资源使用情况
async function loadResourceUsage() {
    try {
        const data = await fetchAPI('/api/resources');
        document.getElementById('cpuUsage').textContent = `${data.cpuUsagePercent}%`;
        document.getElementById('memoryUsage').textContent = `${data.memoryUsageMB} MB`;
        document.getElementById('goroutines').textContent = data.goroutines;
    } catch (error) {
        showStatus(`加载资源使用情况失败: ${error.message}`, true);
    }
}

// 触发垃圾回收
async function triggerGC() {
    try {
        const response = await fetchAPI('/api/resources?action=gc');
        showStatus(response.message);
        setTimeout(loadResourceUsage, 500); // 刷新资源使用情况
    } catch (error) {
        showStatus(`触发垃圾回收失败: ${error.message}`, true);
    }
}
window.onload = () => {
    initTheme(); // 初始化主题
    getSyncStatus();
    loadPaths();
    loadRecycleBinCount();
    setInterval(getSyncStatus, 5000);
    setInterval(loadResourceUsage, 3000);// 每 3 秒刷新资源使用情况
};