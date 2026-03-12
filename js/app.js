(() => {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const preloader = $('#preloader');
    const socContainer = $('#socContainer');
    const sidebar = $('#sidebar');
    const sidebarToggle = $('#sidebarToggle');
    const mobileMenuToggle = $('#mobileMenuToggle');
    const liveClock = $('#liveClock');
    const alertBanner = $('#alertBanner');
    const dismissAlert = $('#dismissAlert');
    const alertsBtn = $('#alertsBtn');
    const notificationPanel = $('#notificationPanel');
    const notifClose = $('#notifClose');
    const fullscreenBtn = $('#fullscreenBtn');
    const eventFeed = $('#eventFeed');
    const toastContainer = $('#toastContainer');

    let scanCount = 0;
    let prevSeverityCounts = null;
    let currentFilter = 'all';
    let lastUpdateTime = null;

    function getActiveKeys() {
        if (currentFilter === 'all') return ['himatika', 'fotografi'];
        return [currentFilter];
    }

    function getFilteredEvents(events) {
        if (!events) return [];
        if (currentFilter === 'all') return events;
        return events.filter(e => e.site_key === currentFilter);
    }

    window.addEventListener('load', () => {
        setTimeout(() => {
            preloader.classList.add('hidden');
            socContainer.classList.add('visible');
            initDashboard();
        }, 2000);
    });

    function initDashboard() {
        SOCCharts.initAll();
        startClock();
        bindEvents();

        SOCData.connect();

        SOCData.onUpdate('scan', onScanData);
        SOCData.onUpdate('dashboard', onDashboardData);
        SOCData.onUpdate('events', onEventsData);
        SOCData.onUpdate('logs', onLogsData);
        SOCData.onUpdate('connection', onConnectionChange);

        showToast('info', 'Dasbor SOC diinisialisasi — menghubungkan ke backend pemantauan...');
    }

    function startClock() {
        function tick() {
            const now = new Date();
            liveClock.textContent = now.toLocaleTimeString('en-GB', { timeZone: 'UTC' });
        }
        tick();
        setInterval(tick, 1000);
    }

    function bindEvents() {
        $$('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = link.dataset.page;
                navigateTo(page);
            });
        });

        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });

        mobileMenuToggle.addEventListener('click', () => {
            sidebar.classList.toggle('mobile-open');
        });

        document.querySelector('.main-content').addEventListener('click', () => {
            sidebar.classList.remove('mobile-open');
        });

        dismissAlert.addEventListener('click', () => {
            alertBanner.classList.add('hidden');
        });

        alertsBtn.addEventListener('click', () => {
            notificationPanel.classList.toggle('open');
        });
        notifClose.addEventListener('click', () => {
            notificationPanel.classList.remove('open');
        });

        fullscreenBtn.addEventListener('click', toggleFullscreen);

        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                $('#globalSearch').focus();
            }
            if (e.key === 'Escape') {
                notificationPanel.classList.remove('open');
            }
        });

        const incidentFilter = $('#incidentFilter');
        if (incidentFilter) {
            incidentFilter.addEventListener('change', () => {
                renderIncidentTable(incidentFilter.value);
            });
        }

        $$('.chart-btn[data-range]').forEach(btn => {
            btn.addEventListener('click', () => {
                $$('.chart-btn[data-range]').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });
        });

        const exportBtn = $('#exportIncidents');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                showToast('success', 'Laporan insiden berhasil diekspor');
            });
        }

        const scanBtn = $('#scanNowBtn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                SOCData.requestScan();
                showToast('info', 'Pemindaian manual dipicu — menunggu hasil...');
            });
        }

        const websiteFilter = $('#websiteFilter');
        if (websiteFilter) {
            websiteFilter.addEventListener('change', () => {
                currentFilter = websiteFilter.value;
                applyWebsiteFilter();
            });
        }
    }

    function navigateTo(page) {
        $$('.nav-link').forEach(l => l.classList.remove('active'));
        const activeLink = document.querySelector(`.nav-link[data-page="${page}"]`);
        if (activeLink) activeLink.classList.add('active');

        $$('.page-content').forEach(p => p.classList.remove('active'));
        const activePage = $(`#page-${page}`);
        if (activePage) activePage.classList.add('active');

        const currentPage = $('#currentPage');
        if (currentPage) {
            currentPage.textContent = activeLink ? activeLink.querySelector('span').textContent : page;
        }

        sidebar.classList.remove('mobile-open');
    }

    function applyWebsiteFilter() {
        const himCard = $('#card-himatika');
        const fotoCard = $('#card-fotografi');
        if (himCard) himCard.style.display = (currentFilter === 'all' || currentFilter === 'himatika') ? '' : 'none';
        if (fotoCard) fotoCard.style.display = (currentFilter === 'all' || currentFilter === 'fotografi') ? '' : 'none';

        const scanData = SOCData.getLatestScan();
        const dashData = SOCData.getDashboard();
        const events = SOCData.getEvents();

        if (Object.keys(scanData).length) {
            onScanData(scanData);
        }
        if (dashData && Object.keys(dashData).length) {
            onDashboardData(dashData);
        }
        if (events.length) {
            onEventsData(events);
        }

        SOCCharts.setFilter(currentFilter);

        const label = currentFilter === 'all' ? 'Semua Website' :
            currentFilter === 'himatika' ? 'himatikafmipaunhas' : 'ukmfotografiunhas.com';
        showToast('info', 'Filter dasbor: ' + label);
    }

    function toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen();
            fullscreenBtn.innerHTML = '<i class="fas fa-compress"></i>';
        } else {
            document.exitFullscreen();
            fullscreenBtn.innerHTML = '<i class="fas fa-expand"></i>';
        }
    }

    function onScanData(data) {
        scanCount++;
        lastUpdateTime = new Date();
        updateLastUpdated();
        updateWebsiteCards(data);
        updateAllDashboardStats(data);
        updateHealthRings(data);
        updateNetworkStats(data);
        SOCCharts.updateFromScan(data);
        renderSecurityHeaders(data);
        renderConnectionRadar(data);
        renderBlockedIPs(data);
        renderVulnerabilities(data);
        updateVulnSummary(data);
        renderEndpoints(data);
        renderFirewallRules(data);
        renderAssets(data);
        renderCompliance(data);
    }

    function onDashboardData(data) {
        if (!data) return;

        SOCCharts.updateFromDashboard(data);

        const threatLevelEl = $('#globalThreatLevel');
        if (threatLevelEl) {
            const level = data.threat_level || 'UNKNOWN';
            threatLevelEl.textContent = level;
            threatLevelEl.className = 'threat-value ' + level.toLowerCase();
        }

        if (data.severity_counts) {
            let sc = data.severity_counts;
            let totalEvents = data.total_events || 0;

            if (currentFilter !== 'all') {
                const filteredEvts = getFilteredEvents(SOCData.getEvents());
                sc = { critical: 0, high: 0, medium: 0, warning: 0, low: 0, info: 0 };
                filteredEvts.forEach(e => { if (sc[e.severity] !== undefined) sc[e.severity]++; });
                totalEvents = filteredEvts.length;
            }

            const critHigh = (sc.critical || 0) + (sc.high || 0);
            const warnings = (sc.warning || 0) + (sc.medium || 0);

            setEl('totalThreats', totalEvents);
            setEl('activeIncidents', critHigh);
            setEl('suspiciousIPs', warnings);

            const scores = [];
            if (data.websites) {
                for (const key of Object.keys(data.websites)) {
                    if (currentFilter !== 'all' && key !== currentFilter) continue;
                    const site = data.websites[key];
                    if (site && typeof site.security_score === 'number') {
                        scores.push(site.security_score);
                    }
                }
            }
            const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
            setEl('blockedAttacks', avgScore + '%');
            setEl('monitoredAssets', currentFilter === 'all' ? (data.monitored_assets || 2) : 1);
            setEl('totalTraffic', scanCount);

            updateTrends(sc);

            setEl('navBadgeThreat', totalEvents);
            setEl('navBadgeIncident', critHigh);
            setEl('notifBadge', totalEvents);

            updateAlertBanner(sc, data);
        }

        if (data.events_recent) {
            const filteredRecent = getFilteredEvents(data.events_recent);
            SOCData.updateMITREFromEvents(filteredRecent);
            renderMITREGrid();
            renderNotifications(filteredRecent);
        }
    }

    function onEventsData(events) {
        if (!Array.isArray(events)) return;
        renderEventFeed(events);
        renderIncidentTable();
        renderIncidentBoard(events);
        renderThreatIntel(events);
    }

    function onLogsData(logs) {
        if (!Array.isArray(logs)) return;
        renderLogViewer(logs);
    }

    function onConnectionChange(info) {
        if (info.status === 'connected') {
            showToast('success', 'Terhubung ke backend pemantauan SOC');
            const connDot = $('#connectionStatus');
            if (connDot) connDot.className = 'connection-dot online';
        } else {
            showToast('critical', 'Koneksi ke backend SOC terputus — mencoba menghubungkan kembali...');
            const connDot = $('#connectionStatus');
            if (connDot) connDot.className = 'connection-dot offline';
        }
    }

    function updateAlertBanner(sc, data) {
        const alertMsg = $('#alertMessage');
        if (!alertMsg) return;

        const critCount = sc.critical || 0;
        const highCount = sc.high || 0;
        const total = critCount + highCount;

        if (critCount > 0) {
            alertMsg.innerHTML = `<strong>PERINGATAN KRITIS:</strong> ${critCount} peristiwa keamanan kritis terdeteksi di situs terpantau — ${total} total peringatan prioritas tinggi`;
            alertBanner.className = 'alert-banner critical';
            alertBanner.classList.remove('hidden');
        } else if (highCount > 0) {
            alertMsg.innerHTML = `<strong>PERINGATAN:</strong> ${highCount} peristiwa tingkat tinggi terdeteksi — pemantauan berlanjut`;
            alertBanner.className = 'alert-banner warning';
            alertBanner.classList.remove('hidden');
        } else {
            alertMsg.innerHTML = `<strong>AMAN:</strong> Tidak ada peringatan kritis — sistem beroperasi normal`;
            alertBanner.className = 'alert-banner success';
        }
    }

    function updateTrends(sc) {
        if (prevSeverityCounts) {
            setTrend('trendThreats', (sc.critical || 0) + (sc.high || 0) + (sc.medium || 0) + (sc.warning || 0), (prevSeverityCounts.critical || 0) + (prevSeverityCounts.high || 0) + (prevSeverityCounts.medium || 0) + (prevSeverityCounts.warning || 0));
            setTrend('trendIncidents', (sc.critical || 0) + (sc.high || 0), (prevSeverityCounts.critical || 0) + (prevSeverityCounts.high || 0));
            setTrend('trendWarnings', (sc.warning || 0) + (sc.medium || 0), (prevSeverityCounts.warning || 0) + (prevSeverityCounts.medium || 0));
        } else {
            setTrendText('trendThreats', 'neutral', 'Langsung');
            setTrendText('trendIncidents', 'neutral', 'Langsung');
            setTrendText('trendScore', 'neutral', 'Langsung');
            setTrendText('trendAssets', 'neutral', 'Stabil');
            setTrendText('trendWarnings', 'neutral', 'Langsung');
            setTrendText('trendScans', 'up', 'Aktif');
        }
        prevSeverityCounts = { ...sc };
    }

    function setTrend(id, current, previous) {
        const el = $(`#${id}`);
        if (!el) return;
        const diff = current - previous;
        if (diff > 0) {
            el.className = 'stat-trend up';
            el.innerHTML = `<i class="fas fa-arrow-up"></i> +${diff}`;
        } else if (diff < 0) {
            el.className = 'stat-trend down';
            el.innerHTML = `<i class="fas fa-arrow-down"></i> ${diff}`;
        } else {
            el.className = 'stat-trend neutral';
            el.innerHTML = `<i class="fas fa-minus"></i> 0`;
        }
    }

    function setTrendText(id, dir, text) {
        const el = $(`#${id}`);
        if (!el) return;
        const icons = { up: 'fa-arrow-up', down: 'fa-arrow-down', neutral: 'fa-minus' };
        el.className = 'stat-trend ' + dir;
        el.innerHTML = `<i class="fas ${icons[dir]}"></i> ${text}`;
    }

    function updateWebsiteCards(scanData) {
        const himCard = $('#card-himatika');
        const fotoCard = $('#card-fotografi');
        if (himCard) himCard.style.display = (currentFilter === 'all' || currentFilter === 'himatika') ? '' : 'none';
        if (fotoCard) fotoCard.style.display = (currentFilter === 'all' || currentFilter === 'fotografi') ? '' : 'none';

        for (const key of getActiveKeys()) {
            const prefix = key === 'himatika' ? 'him' : 'foto';
            const site = scanData[key];
            if (!site) continue;

            const card = $(`#card-${key}`);
            if (card) {
                const statusEl = card.querySelector('.website-status');
                const dotEl = card.querySelector('.website-dot');
                if (statusEl) {
                    statusEl.textContent = site.status.toUpperCase();
                    statusEl.className = 'website-status ' + (site.status === 'online' ? 'online' : 'offline');
                }
                if (dotEl) {
                    dotEl.className = 'website-dot ' + (site.status === 'online' ? 'online' : 'offline');
                }
            }

            setEl(`${prefix}-uptime`, (site.uptime_percent || 0) + '%');
            setEl(`${prefix}-response`, site.response_time_ms + 'ms');
            setEl(`${prefix}-threats`, (site.security_score || 0) + '%');
            setEl(`${prefix}-ssl`, site.ssl && site.ssl.valid ? 'Valid' : 'TIDAK VALID');

            if (site.security_headers) {
                const total = Object.keys(site.security_headers).length;
                const present = Object.values(site.security_headers).filter(h => h.present).length;
                const presentPct = Math.round((present / total) * 100);
                const missingPct = 100 - presentPct;

                const barId = `${prefix}-threat-bar`;
                const barContainer = $(`#${barId}`);
                if (barContainer) {
                    barContainer.innerHTML = `
                        <div class="threat-bar-item low" style="width: ${presentPct}%;" title="Aman: ${presentPct}%"></div>
                        <div class="threat-bar-item critical" style="width: ${missingPct}%;" title="Tidak Ada: ${missingPct}%"></div>
                    `;
                }
            }
        }
    }

    function updateAllDashboardStats(scanData) {
        const events = getFilteredEvents(SOCData.getEvents());

        for (const key of getActiveKeys()) {
            const prefix = key === 'himatika' ? 'him' : 'foto';
            const site = scanData[key];
            if (!site) continue;
            setEl(`${prefix}-response`, site.response_time_ms + 'ms');
        }

        setEl('liveAttacks', events.filter(e => e.severity === 'critical').length);
        setEl('countriesBlocked', '0');
        setEl('ipsBlacklisted', events.filter(e => e.severity === 'high').length);
    }

    function updateNetworkStats(scanData) {
        const activeKeys = getActiveKeys();
        const events = getFilteredEvents(SOCData.getEvents());
        const sites = activeKeys.map(k => scanData[k]).filter(Boolean);

        setEl('netInbound', sites.length >= 1 ? sites[0].response_time_ms + ' ms' : '--');
        setEl('netOutbound', sites.length >= 2 ? sites[1].response_time_ms + ' ms' : '--');

        let onlineCount = 0;
        sites.forEach(s => { if (s.status === 'online') onlineCount++; });
        setEl('netConnections', onlineCount + ' / ' + activeKeys.length);

        setEl('netAnomalies', events.filter(e => e.severity === 'critical' || e.severity === 'high').length);
    }

    function updateHealthRings(scanData) {
        const circumference = 2 * Math.PI * 54;

        function animateRing(ringId, progressId, valueId, percent, color) {
            const ring = $(`#${ringId}`);
            const progress = $(`#${progressId}`);
            const valueEl = $(`#${valueId}`);
            if (!ring || !progress) return;

            ring.dataset.percent = percent;
            ring.dataset.color = color;
            progress.style.strokeDasharray = circumference;
            progress.style.stroke = color;
            const offset = circumference - (percent / 100) * circumference;
            progress.style.strokeDashoffset = offset;
            if (valueEl) valueEl.textContent = percent + '%';
        }

        const him = (currentFilter === 'all' || currentFilter === 'himatika') ? scanData.himatika : null;
        const foto = (currentFilter === 'all' || currentFilter === 'fotografi') ? scanData.fotografi : null;

        let himHealth = 0;
        if (him) {
            himHealth = him.status === 'online' ? Math.min(100, Math.round((him.security_score || 0) * 0.6 + (him.ssl && him.ssl.valid ? 20 : 0) + (him.uptime_percent > 90 ? 20 : him.uptime_percent > 50 ? 10 : 0))) : 0;
        }
        animateRing('ringHimatika', 'healthCPU', 'healthValHim', himHealth, himHealth > 70 ? '#00ff88' : himHealth > 40 ? '#f59e0b' : '#ff3b5c');

        let fotoHealth = 0;
        if (foto) {
            fotoHealth = foto.status === 'online' ? Math.min(100, Math.round((foto.security_score || 0) * 0.6 + (foto.ssl && foto.ssl.valid ? 20 : 0) + (foto.uptime_percent > 90 ? 20 : foto.uptime_percent > 50 ? 10 : 0))) : 0;
        }
        animateRing('ringFotografi', 'healthRAM', 'healthValFoto', fotoHealth, fotoHealth > 70 ? '#a855f7' : fotoHealth > 40 ? '#f59e0b' : '#ff3b5c');

        let sslHealth = 0;
        let sslCount = 0;
        for (const site of [him, foto]) {
            if (site && site.ssl) {
                sslCount++;
                if (site.ssl.valid) sslHealth += 100;
            }
        }
        const sslPct = sslCount > 0 ? Math.round(sslHealth / sslCount) : 0;
        animateRing('ringSSL', 'healthDisk', 'healthValSSL', sslPct, sslPct > 70 ? '#00d4ff' : sslPct > 40 ? '#f59e0b' : '#ff3b5c');

        const overallPct = Math.round((himHealth + fotoHealth + sslPct) / 3);
        animateRing('ringOverall', 'healthNetwork', 'healthValOverall', overallPct, overallPct > 70 ? '#f59e0b' : overallPct > 40 ? '#f59e0b' : '#ff3b5c');
    }

    function updateVulnSummary(scanData) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        let totalVulns = 0;

        for (const key of getActiveKeys()) {
            const site = scanData[key];
            if (!site || !site.security_headers) continue;

            for (const [header, info] of Object.entries(site.security_headers)) {
                if (!info.present) {
                    if (header === 'Strict-Transport-Security' || header === 'Content-Security-Policy') {
                        counts.high++;
                    } else if (header === 'X-Frame-Options' || header === 'X-Content-Type-Options') {
                        counts.medium++;
                    } else if (header === 'X-XSS-Protection') {
                        counts.low++;
                    } else {
                        counts.medium++;
                    }
                    totalVulns++;
                }
            }

            if (site.ssl && !site.ssl.valid) {
                counts.critical++;
                totalVulns++;
            } else if (site.ssl && site.ssl.days_remaining > 0 && site.ssl.days_remaining < 30) {
                counts.medium++;
                totalVulns++;
            }
        }

        setEl('vulnCritical', counts.critical);
        setEl('vulnHigh', counts.high);
        setEl('vulnMedium', counts.medium);
        setEl('vulnLow', counts.low);
        setEl('vulnInfo', counts.info);
        setEl('navBadgeVuln', totalVulns);
    }

    function renderSecurityHeaders(scanData) {
        const container = $('#attackOrigins');
        if (!container) return;

        const headerItems = [];
        for (const key of getActiveKeys()) {
            const site = scanData[key];
            if (!site || !site.security_headers) continue;

            for (const [headerName, info] of Object.entries(site.security_headers)) {
                headerItems.push({
                    site: site.name,
                    header: headerName,
                    present: info.present,
                    value: info.value
                });
            }
        }

        const grouped = {};
        headerItems.forEach(item => {
            if (!grouped[item.header]) grouped[item.header] = [];
            grouped[item.header].push(item);
        });

        const headerNames = Object.keys(grouped);
        container.innerHTML = headerNames.slice(0, 10).map(header => {
            const items = grouped[header];
            const allPresent = items.every(i => i.present);
            const anyPresent = items.some(i => i.present);
            const color = allPresent ? '#00ff88' : anyPresent ? '#f59e0b' : '#ff3b5c';
            const status = allPresent ? 'Ada' : anyPresent ? 'Sebagian' : 'Tidak Ada';
            const percent = Math.round((items.filter(i => i.present).length / items.length) * 100);

            return `
                <div class="geo-item">
                    <span class="geo-flag"><i class="fas ${allPresent ? 'fa-shield-halved' : 'fa-triangle-exclamation'}" style="color:${color}"></i></span>
                    <div class="geo-info">
                        <span class="geo-country">${sanitize(header)}</span>
                        <span class="geo-count">${status}</span>
                    </div>
                    <div class="geo-bar-bg">
                        <div class="geo-bar" style="width: ${percent}%; background: ${color};"></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderEventFeed(events) {
        if (!eventFeed) return;
        const evts = getFilteredEvents(events || SOCData.getEvents());
        if (!evts.length) {
            eventFeed.innerHTML = '<div class="event-item"><div class="event-content"><div class="event-title" style="color:var(--text-muted)">Menunggu data pemindaian...</div></div></div>';
            return;
        }

        eventFeed.innerHTML = evts.slice(0, 30).map(ev => {
            const sevClass = ev.severity === 'critical' ? 'critical' : ev.severity === 'high' ? 'high' : ev.severity === 'warning' ? 'warning' : ev.severity === 'medium' ? 'medium' : 'low';
            return `
                <div class="event-item">
                    <div class="event-severity ${sevClass}"></div>
                    <div class="event-content">
                        <div class="event-title">${sanitize(ev.title || '')}</div>
                        <div class="event-details">
                            <span><i class="fas fa-globe"></i> ${sanitize(ev.site_name || '')}</span>
                            <span><i class="fas fa-info-circle"></i> ${sanitize(ev.severity || '').toUpperCase()}</span>
                        </div>
                    </div>
                    <span class="event-time">${SOCData.timeSince(ev.timestamp)}</span>
                </div>
            `;
        }).join('');
    }

    function renderIncidentTable(filter) {
        const tbody = $('#incidentTableBody');
        if (!tbody) return;

        let events = getFilteredEvents(SOCData.getEvents());
        if (!events.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted)">Menunggu data pemindaian...</td></tr>';
            return;
        }

        if (filter && filter !== 'all') {
            events = events.filter(e => e.severity === filter);
        }

        tbody.innerHTML = events.slice(0, 20).map(ev => {
            const website = SOCData.websites[ev.site_key] || { name: ev.site_name || 'Tidak diketahui' };
            return `
                <tr>
                    <td><span style="font-family: var(--font-mono); color: var(--accent-cyan); font-size: 0.75rem;">${sanitize(ev.id || '')}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem;">${SOCData.formatTime(ev.timestamp)}</td>
                    <td><span class="website-tag ${ev.site_key || ''}">${sanitize(website.name)}</span></td>
                    <td>${sanitize(ev.title || '')}</td>
                    <td><span class="ip-text">\u2014</span></td>
                    <td><span class="severity-badge ${ev.severity}">${(ev.severity || '').toUpperCase()}</span></td>
                    <td><span class="status-badge open">Terbuka</span></td>
                    <td><button class="action-btn" onclick="SOCApp.investigateIncident('${sanitize(ev.id || '')}')">Investigasi</button></td>
                </tr>
            `;
        }).join('');
    }

    function renderMITREGrid() {
        const grid = $('#mitreGrid');
        if (!grid) return;
        grid.innerHTML = SOCData.mitreAttack.map(item => {
            const countClass = item.level === 'high' ? 'high-count' : item.level === 'med' ? 'med-count' : 'low-count';
            return `
                <div class="mitre-item">
                    <span class="mitre-id">${sanitize(item.id)}</span>
                    <span class="mitre-name">${sanitize(item.name)}</span>
                    <span class="mitre-count ${countClass}">${item.count}</span>
                </div>
            `;
        }).join('');
    }

    function renderBlockedIPs(scanData) {
        const container = $('#blockedIPsList');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const ips = [];

        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site || !site.dns || !site.dns.ip_addresses) continue;
            site.dns.ip_addresses.forEach(ip => {
                ips.push({
                    ip: ip,
                    label: site.name,
                    dns_time: site.dns.resolution_time_ms || 0,
                    status: site.status,
                    score: site.security_score
                });
            });
        }

        if (!ips.length) {
            container.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px;">Menunggu data DNS...</div>';
            return;
        }

        const maxDns = Math.max(...ips.map(i => i.dns_time), 1);
        container.innerHTML = ips.map(item => `
            <div class="blocked-ip-item">
                <span class="blocked-ip-address">${sanitize(item.ip)}</span>
                <span class="blocked-ip-country">${sanitize(item.label)}</span>
                <div class="blocked-ip-bar">
                    <div class="blocked-ip-fill" style="width: ${(item.dns_time / maxDns) * 100}%"></div>
                </div>
                <span class="blocked-ip-count">${item.dns_time}ms</span>
            </div>
        `).join('');
    }

    function renderNotifications(events) {
        const container = $('#notifList');
        if (!container) return;

        const evts = getFilteredEvents(events || SOCData.getEvents());
        if (!evts.length) return;

        container.innerHTML = evts.slice(0, 10).map(ev => {
            const icons = {
                critical: 'fa-skull-crossbones',
                high: 'fa-circle-exclamation',
                medium: 'fa-triangle-exclamation',
                warning: 'fa-triangle-exclamation',
                low: 'fa-info-circle',
                info: 'fa-info-circle'
            };
            return `
                <div class="notif-item">
                    <div class="notif-icon ${ev.severity}">
                        <i class="fas ${icons[ev.severity] || 'fa-bell'}"></i>
                    </div>
                    <div class="notif-content">
                        <div class="notif-title">${sanitize(ev.title || '')}</div>
                        <div class="notif-text">${sanitize(ev.description || '')}</div>
                        <div class="notif-time">${SOCData.timeSince(ev.timestamp)}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderIncidentBoard(events) {
        const evts = getFilteredEvents(events || SOCData.getEvents());

        const buckets = {
            new: evts.filter(e => e.severity === 'critical'),
            investigating: evts.filter(e => e.severity === 'high'),
            containment: evts.filter(e => e.severity === 'medium' || e.severity === 'warning'),
            resolved: evts.filter(e => e.severity === 'low' || e.severity === 'info')
        };

        setEl('countNew', buckets.new.length);
        setEl('countInvestigating', buckets.investigating.length);
        setEl('countContainment', buckets.containment.length);
        setEl('countResolved', buckets.resolved.length);

        for (const [cat, items] of Object.entries(buckets)) {
            const container = $(`#incidents${capitalize(cat)}`);
            if (!container) continue;
            container.innerHTML = items.slice(0, 5).map(ev => {
                const website = SOCData.websites[ev.site_key] || { name: ev.site_name || '' };
                return `
                    <div class="incident-card">
                        <div class="incident-card-title">${sanitize(ev.id || '')}: ${sanitize(ev.title || '')}</div>
                        <div class="incident-card-meta">
                            <span class="severity-badge ${ev.severity}">${(ev.severity || '').toUpperCase()}</span>
                            <span class="website-tag ${ev.site_key || ''}">${sanitize(website.name)}</span>
                        </div>
                        <div class="incident-card-meta" style="margin-top:6px;">
                            <span style="color:var(--text-muted);font-size:0.65rem"><i class="fas fa-clock"></i> ${SOCData.timeSince(ev.timestamp)}</span>
                        </div>
                    </div>
                `;
            }).join('') || '<div style="color:var(--text-muted);text-align:center;padding:10px;font-size:0.7rem">Tidak ada item</div>';
        }
    }

    function renderLogViewer(logs) {
        const container = $('#logViewer');
        if (!container) return;

        const logData = logs || SOCData.getLogs();
        if (!logData.length) {
            container.innerHTML = '<div class="log-entry"><span class="log-message" style="color:var(--text-muted)">Menunggu log pemantauan...</span></div>';
            return;
        }

        container.innerHTML = logData.slice(0, 100).map(l => `
            <div class="log-entry">
                <span class="log-time">${SOCData.formatTime(l.timestamp)}</span>
                <span class="log-level ${l.level}">${sanitize(l.level)}</span>
                <span class="log-source">${sanitize(l.source || 'Pemantau')}</span>
                <span class="log-message">${sanitize(l.message || '')}</span>
            </div>
        `).join('');
    }

    function renderConnectionRadar(scanData) {
        const overlay = $('#mapOverlay');
        if (!overlay) return;

        const dots = [];
        let idx = 0;
        for (const key of getActiveKeys()) {
            const site = scanData[key];
            if (!site) continue;
            const severity = site.status === 'online' ?
                (site.security_score > 70 ? 'low' : site.security_score > 40 ? 'medium' : 'high') :
                'critical';
            const left = idx === 0 ? '68%' : '76%';
            const top = idx === 0 ? '58%' : '66%';
            dots.push(`<div class="attack-dot ${severity}" style="left:${left};top:${top};" title="${sanitize(site.name)}: ${site.status.toUpperCase()} | Skor: ${site.security_score}% | ${site.response_time_ms}ms"></div>`);
            idx++;
        }
        overlay.innerHTML = dots.join('');
    }

    function renderThreatIntel(events) {
        const evts = getFilteredEvents(events || SOCData.getEvents());

        const malwareContainer = $('#malwareCampaigns');
        if (malwareContainer) {
            const critEvents = evts.filter(e => e.severity === 'critical');
            if (critEvents.length > 0) {
                malwareContainer.innerHTML = critEvents.slice(0, 5).map(ev => `
                    <div class="intel-item">
                        <div class="intel-item-title">${sanitize(ev.title || '')}</div>
                        <div class="intel-item-desc">${sanitize(ev.description || '')}</div>
                        <div class="intel-item-meta">
                            <span class="intel-meta-tag severity-badge critical">CRITICAL</span>
                            <span style="font-size:0.65rem;color:var(--text-muted)">${sanitize(ev.site_name || '')} \u2014 ${SOCData.timeSince(ev.timestamp)}</span>
                        </div>
                    </div>
                `).join('');
            } else {
                malwareContainer.innerHTML = `
                    <div class="intel-item">
                        <div class="intel-item-title">Tidak Ada Kampanye Kritis Aktif</div>
                        <div class="intel-item-desc">Semua website terpantau beroperasi tanpa ancaman kritis</div>
                        <div class="intel-item-meta">
                            <span class="intel-meta-tag severity-badge low">CLEAR</span>
                            <span style="font-size:0.65rem;color:var(--text-muted)">Last scan: ${SOCData.timeSince(new Date().toISOString())}</span>
                        </div>
                    </div>
                `;
            }
        }

        const iocContainer = $('#iocIndicators');
        if (iocContainer) {
            const critical = evts.filter(e => e.severity === 'critical' || e.severity === 'high');
            iocContainer.innerHTML = critical.slice(0, 8).map(ev => `
                <div class="intel-item">
                    <div class="intel-item-title">[${sanitize(ev.severity.toUpperCase())}] ${sanitize(ev.title || '')}</div>
                    <div class="intel-item-desc">${sanitize(ev.description || '')}</div>
                    <div class="intel-item-meta">
                        <span class="intel-meta-tag severity-badge ${ev.severity}">${ev.severity.toUpperCase()}</span>
                        <span style="font-size:0.65rem;color:var(--text-muted)">${sanitize(ev.site_name || '')} \u2014 ${SOCData.timeSince(ev.timestamp)}</span>
                    </div>
                </div>
            `).join('') || '<div style="color:var(--text-muted);padding:12px;font-size:0.75rem;">Tidak ada indikator IOC kritis terdeteksi.</div>';
        }

        const aptContainer = $('#aptGroups');
        if (aptContainer) {
            const scan = SOCData.getLatestScan();
            const items = [];
            for (const key of getActiveKeys()) {
                const site = scan[key];
                if (!site) continue;
                items.push(`
                    <div class="intel-item">
                        <div class="intel-item-title">${sanitize(site.name)} — Monitor Aktif</div>
                        <div class="intel-item-desc">Status: ${site.status.toUpperCase()} | Respons: ${site.response_time_ms}ms | Keamanan: ${site.security_score}%</div>
                        <div class="intel-item-desc" style="margin-top:4px;">Server: <span style="font-family:var(--font-mono);color:var(--accent-cyan)">${sanitize(site.server || 'Tidak diketahui')}</span> | Teknologi: ${sanitize((site.technologies || []).join(', ') || 'N/A')}</div>
                        <div class="intel-item-meta">
                            <span class="intel-meta-tag severity-badge ${site.status === 'online' ? 'low' : 'critical'}">${site.status.toUpperCase()}</span>
                            <span style="font-size:0.65rem;color:var(--text-muted)">${SOCData.timeSince(site.timestamp)}</span>
                        </div>
                    </div>
                `);
            }
            aptContainer.innerHTML = items.join('') || '<div style="color:var(--text-muted);padding:12px;font-size:0.75rem;">Menunggu data pemindaian...</div>';
        }

        const feedContainer = $('#threatFeed');
        if (feedContainer) {
            feedContainer.innerHTML = evts.slice(0, 10).map(ev => `
                <div class="intel-item">
                    <div class="intel-item-title">${sanitize(ev.title || '')}</div>
                    <div class="intel-item-desc">${sanitize(ev.description || '')}</div>
                    <div class="intel-item-meta">
                        <span class="intel-meta-tag severity-badge ${ev.severity}">${(ev.severity || '').toUpperCase()}</span>
                        <span style="font-size:0.65rem;color:var(--text-muted)">${sanitize(ev.site_name || '')} \u2014 ${SOCData.timeSince(ev.timestamp)}</span>
                    </div>
                </div>
            `).join('') || '<div style="color:var(--text-muted);padding:12px;font-size:0.75rem;">Menunggu peristiwa...</div>';
        }
    }

    function renderVulnerabilities(scanData) {
        const container = $('#vulnList');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const vulns = [];
        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site || !site.security_headers) continue;

            for (const [header, info] of Object.entries(site.security_headers)) {
                if (!info.present) {
                    let severity = 'medium';
                    let desc = `Header ${header} tidak ada`;
                    let cvss = 4.0;

                    if (header === 'Strict-Transport-Security') {
                        severity = 'high'; desc = 'Tidak ada HSTS \u2014 rentan terhadap serangan penurunan protokol'; cvss = 7.4;
                    } else if (header === 'Content-Security-Policy') {
                        severity = 'high'; desc = 'No CSP \u2014 increased risk of XSS and injection attacks'; cvss = 6.5;
                    } else if (header === 'X-Frame-Options') {
                        severity = 'medium'; desc = 'Perlindungan clickjacking tidak ada'; cvss = 4.3;
                    } else if (header === 'X-Content-Type-Options') {
                        severity = 'medium'; desc = 'Perlindungan MIME sniffing tidak ada'; cvss = 4.0;
                    } else if (header === 'X-XSS-Protection') {
                        severity = 'low'; desc = 'Filter XSS lama tidak diaktifkan'; cvss = 3.0;
                    } else if (header === 'Referrer-Policy') {
                        severity = 'medium'; desc = 'Informasi referrer mungkin bocor ke pihak ketiga'; cvss = 3.5;
                    } else if (header === 'Permissions-Policy') {
                        severity = 'medium'; desc = 'Kebijakan fitur browser tidak diatur'; cvss = 3.5;
                    } else if (header === 'Cross-Origin-Opener-Policy') {
                        severity = 'low'; desc = 'Isolasi lintas-origin tidak dikonfigurasi'; cvss = 3.0;
                    } else if (header === 'Cross-Origin-Resource-Policy') {
                        severity = 'low'; desc = 'Kebijakan berbagi sumber daya tidak diatur'; cvss = 3.0;
                    } else if (header === 'Cross-Origin-Embedder-Policy') {
                        severity = 'low'; desc = 'Kebijakan embedder tidak dikonfigurasi'; cvss = 3.0;
                    }

                    vulns.push({
                        title: `${header} \u2014 ${site.name}`,
                        desc,
                        severity,
                        cvss,
                        cve: 'HEADER-' + header.replace(/[^A-Za-z]/g, '').substring(0, 8).toUpperCase(),
                        asset: site.name
                    });
                }
            }

            if (site.ssl && !site.ssl.valid) {
                vulns.push({
                    title: `Sertifikat SSL Tidak Valid \u2014 ${site.name}`,
                    desc: site.ssl.error || 'Verifikasi sertifikat SSL gagal',
                    severity: 'critical',
                    cvss: 9.1,
                    cve: 'SSL-INVALID',
                    asset: site.name
                });
            } else if (site.ssl && site.ssl.days_remaining > 0 && site.ssl.days_remaining < 30) {
                vulns.push({
                    title: `Sertifikat SSL Akan Kedaluwarsa \u2014 ${site.name}`,
                    desc: `Sertifikat kedaluwarsa dalam ${site.ssl.days_remaining} hari`,
                    severity: 'warning',
                    cvss: 5.0,
                    cve: 'SSL-EXPIRY',
                    asset: site.name
                });
            }

            if (site.response_time_ms > 5000) {
                vulns.push({
                    title: `Waktu Respons Lambat \u2014 ${site.name}`,
                    desc: `Waktu respons ${site.response_time_ms}ms (batas: 5000ms)`,
                    severity: 'warning',
                    cvss: 4.0,
                    cve: 'PERF-SLOW',
                    asset: site.name
                });
            }
        }

        vulns.sort((a, b) => b.cvss - a.cvss);

        container.innerHTML = vulns.map(v => `
            <div class="vuln-item">
                <div class="vuln-severity-dot ${v.severity}"></div>
                <div class="vuln-info">
                    <div class="vuln-title">${sanitize(v.title)}</div>
                    <div class="vuln-desc">${sanitize(v.desc)}</div>
                </div>
                <span class="vuln-cve">${sanitize(v.cve)}</span>
                <span class="severity-badge ${v.severity}">CVSS ${v.cvss}</span>
                <span class="vuln-asset">${sanitize(v.asset)}</span>
            </div>
        `).join('') || '<div style="color:var(--success);padding:20px;text-align:center;">No vulnerabilities detected!</div>';
    }

    function renderEndpoints(scanData) {
        const container = $('#endpointGrid');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const endpoints = [];
        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site) continue;

            const health = site.status === 'online' ?
                (site.security_score > 70 ? 'healthy' : site.security_score > 40 ? 'warning' : 'critical') :
                'critical';

            endpoints.push({
                name: site.name,
                type: 'Server Web',
                ip: (site.dns && site.dns.ip_addresses && site.dns.ip_addresses[0]) || 'Tidak terselesaikan',
                site: site.url || '',
                health,
                server: site.server || 'Tidak diketahui',
                responseTime: site.response_time_ms,
                statusCode: site.status_code,
                secScore: site.security_score,
                ssl: site.ssl && site.ssl.valid ? 'Valid' : 'Tidak Valid',
                techs: (site.technologies || []).join(', ') || 'N/A',
                uptime: site.uptime_percent || 0
            });
        }

        container.innerHTML = endpoints.map(ep => `
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="endpoint-name"><i class="fas fa-server"></i> ${sanitize(ep.name)}</span>
                    <span class="endpoint-status-dot ${ep.health}"></span>
                </div>
                <div style="font-size:0.7rem;color:var(--text-muted);margin-bottom:10px;">
                    ${sanitize(ep.type)} \u2014 <span class="ip-text">${sanitize(ep.ip)}</span>
                </div>
                <div style="font-size:0.65rem;color:var(--text-muted);margin-bottom:4px;">
                    Server: ${sanitize(ep.server)} | Teknologi: ${sanitize(ep.techs)}
                </div>
                <div class="endpoint-metrics">
                    <div class="ep-metric">
                        <span class="ep-metric-value" style="color:${ep.statusCode === 200 ? 'var(--accent-cyan)' : 'var(--critical)'}">${ep.statusCode}</span>
                        <span class="ep-metric-label">HTTP</span>
                    </div>
                    <div class="ep-metric">
                        <span class="ep-metric-value" style="color:${ep.responseTime < 1000 ? 'var(--accent-cyan)' : ep.responseTime < 3000 ? 'var(--medium)' : 'var(--critical)'}">${ep.responseTime}ms</span>
                        <span class="ep-metric-label">Respons</span>
                    </div>
                    <div class="ep-metric">
                        <span class="ep-metric-value" style="color:${ep.secScore > 70 ? 'var(--success)' : ep.secScore > 40 ? 'var(--medium)' : 'var(--critical)'}">${ep.secScore}%</span>
                        <span class="ep-metric-label">Keamanan</span>
                    </div>
                    <div class="ep-metric">
                        <span class="ep-metric-value" style="color:${ep.ssl === 'Valid' ? 'var(--success)' : 'var(--critical)'}">${ep.ssl}</span>
                        <span class="ep-metric-label">SSL</span>
                    </div>
                    <div class="ep-metric">
                        <span class="ep-metric-value" style="color:var(--accent-cyan)">${ep.uptime}%</span>
                        <span class="ep-metric-label">Waktu Aktif</span>
                    </div>
                </div>
            </div>
        `).join('') || '<div style="color:var(--text-muted);padding:20px;text-align:center;">Waiting for endpoint data...</div>';
    }

    function renderFirewallRules(scanData) {
        const container = $('#firewallRules');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const rules = [];
        let ruleId = 1;

        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site || !site.security_headers) continue;

            const hsts = site.security_headers['Strict-Transport-Security'];
            rules.push({
                id: ruleId++,
                desc: `Penegakan HSTS \u2014 ${site.name}`,
                action: hsts && hsts.present ? 'allow' : 'block',
                protocol: 'HTTPS',
                source: 'Semua Klien',
                dest: site.name,
                status: hsts && hsts.present ? 'Aktif' : 'TIDAK ADA'
            });

            const csp = site.security_headers['Content-Security-Policy'];
            rules.push({
                id: ruleId++,
                desc: `CSP Policy \u2014 ${site.name}`,
                action: csp && csp.present ? 'allow' : 'block',
                protocol: 'HTTP',
                source: 'Skrip Inline',
                dest: site.name,
                status: csp && csp.present ? 'Aktif' : 'TIDAK ADA'
            });

            const xfo = site.security_headers['X-Frame-Options'];
            rules.push({
                id: ruleId++,
                desc: `X-Frame-Options \u2014 ${site.name}`,
                action: xfo && xfo.present ? 'allow' : 'block',
                protocol: 'HTTP',
                source: 'Frame Eksternal',
                dest: site.name,
                status: xfo && xfo.present ? 'Aktif' : 'TIDAK ADA'
            });

            rules.push({
                id: ruleId++,
                desc: `SSL Certificate \u2014 ${site.name}`,
                action: site.ssl && site.ssl.valid ? 'allow' : 'alert',
                protocol: site.ssl ? (site.ssl.protocol || 'TLS') : 'TLS',
                source: 'Semua',
                dest: site.name,
                status: site.ssl && site.ssl.valid ? 'Valid' : 'TIDAK VALID'
            });
        }

        container.innerHTML = `
            <div class="fw-rule" style="background: var(--bg-tertiary); font-weight: 700; font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px;">
                <span>#</span><span>Deskripsi</span><span>Aksi</span><span>Protokol</span><span>Sumber \u2192 Tujuan</span><span>Status</span>
            </div>
        ` + rules.map(r => `
            <div class="fw-rule">
                <span style="font-family:var(--font-mono);color:var(--text-muted)">${r.id}</span>
                <span>${sanitize(r.desc)}</span>
                <span class="fw-action-badge ${r.action}">${r.action.toUpperCase()}</span>
                <span class="fw-protocol">${sanitize(r.protocol)}</span>
                <span class="fw-source">${sanitize(r.source)} \u2192 ${sanitize(r.dest)}</span>
                <span class="fw-hits">${sanitize(r.status)}</span>
            </div>
        `).join('');
    }

    function renderAssets(scanData) {
        const container = $('#assetGrid');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const assets = [
            { name: 'Backend SOC', type: 'Server Pemantauan (Flask + SocketIO)', icon: 'fa-server', status: 'online', lastScan: 'Aktif sekarang' },
            { name: 'Kanal WebSocket', type: 'Umpan Data Waktu Nyata', icon: 'fa-satellite-dish', status: SOCData.isConnected() ? 'online' : 'offline', lastScan: SOCData.isConnected() ? 'Terhubung' : 'Terputus' }
        ];

        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site) continue;
            assets.push({
                name: site.name,
                type: `Aplikasi Web (${site.server || 'Tidak diketahui'})`,
                icon: 'fa-globe',
                status: site.status === 'online' ? 'online' : 'offline',
                lastScan: SOCData.timeSince(site.timestamp)
            });
            if (site.ssl) {
                assets.push({
                    name: `SSL: ${site.name}`,
                    type: site.ssl.valid ? `${site.ssl.protocol || 'TLS'} \u2014 ${site.ssl.cipher || 'N/A'}` : 'Certificate Invalid',
                    icon: 'fa-lock',
                    status: site.ssl.valid ? 'online' : 'offline',
                    lastScan: site.ssl.days_remaining ? `Kedaluwarsa dalam ${site.ssl.days_remaining}h` : 'N/A'
                });
            }
            if (site.dns) {
                assets.push({
                    name: `DNS: ${site.name}`,
                    type: (site.dns.ip_addresses || []).join(', ') || 'Tidak terselesaikan',
                    icon: 'fa-network-wired',
                    status: site.dns.resolved ? 'online' : 'offline',
                    lastScan: site.dns.resolution_time_ms + 'ms'
                });
            }
        }

        container.innerHTML = assets.map(a => {
            const statusColor = a.status === 'online' ? 'var(--success)' : 'var(--critical)';
            return `
                <div class="asset-card">
                    <div class="asset-icon"><i class="fas ${a.icon}"></i></div>
                    <div class="asset-name">${sanitize(a.name)}</div>
                    <div class="asset-type">${sanitize(a.type)}</div>
                    <div class="asset-status-line">
                        <span class="status-badge ${a.status === 'online' ? 'resolved' : 'open'}">
                            <span style="width:6px;height:6px;border-radius:50%;background:${statusColor};display:inline-block"></span>
                            ${capitalize(a.status)}
                        </span>
                    </div>
                    <div style="font-size:0.6rem;color:var(--text-muted);margin-top:8px;">Terakhir: ${sanitize(a.lastScan)}</div>
                </div>
            `;
        }).join('');
    }

    function renderCompliance(scanData) {
        const container = $('#complianceGrid');
        if (!container) return;

        const scan = scanData || SOCData.getLatestScan();
        const frameworks = [];

        for (const key of getActiveKeys()) {
            const site = scan[key];
            if (!site) continue;

            const headers = site.security_headers || {};
            const sslOk = site.ssl && site.ssl.valid;
            const httpsOk = (site.url || '').startsWith('https');

            const items = [
                { name: 'HTTPS Diterapkan', status: httpsOk ? 'pass' : 'fail' },
                { name: 'SSL Valid', status: sslOk ? 'pass' : 'fail' },
                { name: 'Header HSTS', status: headers['Strict-Transport-Security'] && headers['Strict-Transport-Security'].present ? 'pass' : 'fail' },
                { name: 'Header CSP', status: headers['Content-Security-Policy'] && headers['Content-Security-Policy'].present ? 'pass' : 'fail' },
                { name: 'X-Frame-Options', status: headers['X-Frame-Options'] && headers['X-Frame-Options'].present ? 'pass' : 'fail' },
                { name: 'X-Content-Type-Options', status: headers['X-Content-Type-Options'] && headers['X-Content-Type-Options'].present ? 'pass' : 'fail' },
                { name: 'Referrer-Policy', status: headers['Referrer-Policy'] && headers['Referrer-Policy'].present ? 'pass' : 'fail' },
                { name: 'Permissions-Policy', status: headers['Permissions-Policy'] && headers['Permissions-Policy'].present ? 'pass' : 'fail' }
            ];

            const passCount = items.filter(i => i.status === 'pass').length;
            const score = Math.round((passCount / items.length) * 100);

            frameworks.push({
                framework: site.name,
                score,
                color: score > 70 ? '#00ff88' : score > 40 ? '#f59e0b' : '#ff3b5c',
                items
            });
        }

        const allScores = frameworks.map(f => f.score);
        const avgScore = allScores.length ? Math.round(allScores.reduce((a, b) => a + b, 0) / allScores.length) : 0;
        frameworks.push({
            framework: 'Keamanan Keseluruhan',
            score: avgScore,
            color: avgScore > 70 ? '#00ff88' : avgScore > 40 ? '#f59e0b' : '#ff3b5c',
            items: [
                { name: 'Semua Situs Online', status: getActiveKeys().every(k => scan[k] && scan[k].status === 'online') ? 'pass' : 'fail' },
                { name: 'Sertifikat SSL Valid', status: getActiveKeys().every(k => scan[k] && scan[k].ssl && scan[k].ssl.valid) ? 'pass' : 'fail' },
                { name: 'Skor Rata-rata > 50%', status: avgScore > 50 ? 'pass' : 'fail' }
            ]
        });

        container.innerHTML = frameworks.map(c => {
            const circumference = 2 * Math.PI * 24;
            const offset = circumference - (c.score / 100) * circumference;
            return `
                <div class="compliance-card">
                    <div class="compliance-card-header">
                        <span class="compliance-framework">${sanitize(c.framework)}</span>
                        <div class="compliance-score-ring">
                            <svg viewBox="0 0 60 60">
                                <circle cx="30" cy="30" r="24" fill="none" stroke="var(--border-primary)" stroke-width="5"/>
                                <circle cx="30" cy="30" r="24" fill="none" stroke="${c.color}" stroke-width="5"
                                    stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
                            </svg>
                            <span class="compliance-score-value" style="color:${c.color}">${c.score}%</span>
                        </div>
                    </div>
                    <div class="compliance-details">
                        ${c.items.map(item => `
                            <div class="compliance-item">
                                <span>${sanitize(item.name)}</span>
                                <span class="${item.status === 'pass' ? 'compliance-check' : 'compliance-fail'}" style="font-size:0.75rem">
                                    ${item.status === 'pass' ? '<i class="fas fa-check-circle"></i> Lulus' : '<i class="fas fa-times-circle"></i> Gagal'}
                                </span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');
    }

    function showToast(type, message) {
        const icons = {
            critical: 'fa-skull-crossbones',
            warning: 'fa-triangle-exclamation',
            info: 'fa-info-circle',
            success: 'fa-check-circle'
        };
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="fas ${icons[type]}"></i>
            <span class="toast-text">${sanitize(message)}</span>
            <button class="toast-close" onclick="this.parentElement.classList.add('removing'); setTimeout(() => this.parentElement.remove(), 300)">
                <i class="fas fa-xmark"></i>
            </button>
        `;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('removing');
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    }

    function capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    function sanitize(str) {
        if (str === undefined || str === null) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    function setEl(id, val) {
        const el = document.querySelector(`#${id}`);
        if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
    }

    function updateLastUpdated() {
        const el = $('#lastUpdated');
        if (!el || !lastUpdateTime) return;
        const secs = Math.floor((Date.now() - lastUpdateTime.getTime()) / 1000);
        if (secs < 5) el.textContent = 'Baru saja';
        else if (secs < 60) el.textContent = secs + ' detik lalu';
        else el.textContent = Math.floor(secs / 60) + ' menit lalu';
    }
    setInterval(updateLastUpdated, 1000);

    window.SOCApp = {
        investigateIncident: (id) => {
            showToast('info', `Menginvestigasi insiden ${id}...`);
            navigateTo('incidents');
        },
        showToast,
        navigateTo
    };

})();
