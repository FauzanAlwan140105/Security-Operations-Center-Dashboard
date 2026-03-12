/* ═══════════════════════════════════════════════════════════════
   CSOC — CYBER SECURITY OPERATIONS CENTER
   Main Application Controller — Enterprise Grade
   ═══════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    const $ = s => document.querySelector(s);
    const $$ = s => document.querySelectorAll(s);

    /* ── State ── */
    let scanCount = 0;
    let prevSeverityCounts = {};
    let currentFilter = 'all';
    let lastUpdateTime = null;
    let defconLevel = 5;
    let infoconLevel = 5;
    let eventTimestamps = [];
    let resolvedTimestamps = [];

    /* ── Helpers ── */
    function getActiveKeys() {
        if (currentFilter === 'all') return Object.keys(SOCData.websites);
        return [currentFilter];
    }
    function getFilteredEvents(events) {
        if (!events) return [];
        if (currentFilter === 'all') return events;
        return events.filter(e => {
            return (e.site_key || '') === currentFilter;
        });
    }
    function sanitize(str) {
        if (typeof str !== 'string') return '';
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }
    function capitalize(s) {
        if (!s) return '';
        return s.charAt(0).toUpperCase() + s.slice(1);
    }
    function setEl(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val ?? '--';
    }

    /* ── DEFCON / THREATCON Calculation ── */
    function calculateDefcon(data) {
        if (!data) return 5;
        const level = (data.threat_level || '').toUpperCase();
        if (level === 'CRITICAL') return 1;
        if (level === 'HIGH') return 2;
        if (level === 'ELEVATED') return 3;
        const events = SOCData.getEvents() || [];
        const critCount = events.filter(e => e.severity === 'critical').length;
        const highCount = events.filter(e => e.severity === 'high').length;
        if (critCount >= 3) return 1;
        if (critCount >= 1 || highCount >= 5) return 2;
        if (highCount >= 2) return 3;
        if (events.length > 10) return 4;
        return 5;
    }
    function calculateInfocon(data) {
        if (!data) return 5;
        const d = calculateDefcon(data);
        if (d <= 1) return 1;
        if (d <= 2) return 2;
        if (d <= 3) return 3;
        if (d <= 4) return 4;
        return 5;
    }
    const DEFCON_MAP = {
        1: { status: 'MAXIMUM', color: '#ff2d55' },
        2: { status: 'SIAGA TINGGI', color: '#ff6b35' },
        3: { status: 'WASPADA', color: '#f59e0b' },
        4: { status: 'SIAGA', color: '#3b82f6' },
        5: { status: 'NORMAL', color: '#00ff88' }
    };
    function updateDefconDisplay() {
        const el = $('#defconLevel');
        const statusEl = $('#defconStatus');
        const display = $('.defcon-display');
        const info = DEFCON_MAP[defconLevel] || DEFCON_MAP[5];
        if (el) el.textContent = defconLevel;
        if (statusEl) statusEl.textContent = info.status;
        if (display) display.setAttribute('data-level', defconLevel);
        if (el) el.style.color = info.color;
        // INFOCON
        setEl('infoconLevel', infoconLevel);
        const infoEl = $('#infoconLevel');
        if (infoEl) {
            const ic = DEFCON_MAP[infoconLevel] || DEFCON_MAP[5];
            infoEl.style.color = ic.color;
        }
    }

    /* ── SOC Metrics ── */
    function updateSOCMetrics() {
        const events = SOCData.getEvents() || [];
        // MTTD — Mean Time to Detect (simulated from scan interval)
        const scanInterval = 15; // seconds
        const mttd = Math.max(5, scanInterval + Math.floor(Math.random() * 10));
        setEl('metricMTTD', mttd + 'd');

        // MTTR — Mean Time to Respond (simulated)
        const mttr = Math.max(8, mttd + Math.floor(Math.random() * 20) + 5);
        setEl('metricMTTR', mttr + 'd');

        // False Positive Rate
        const total = events.length || 1;
        const fpRate = Math.max(2, Math.min(15, Math.floor(100 / total) + Math.floor(Math.random() * 5)));
        setEl('metricFPR', fpRate + '%');

        // Escalation Rate
        const critHigh = events.filter(e => e.severity === 'critical' || e.severity === 'high').length;
        const escRate = total > 0 ? Math.round((critHigh / total) * 100) : 0;
        setEl('metricEscRate', escRate + '%');

        // Security Posture
        const dashboard = SOCData.getDashboard();
        let avgScore = '--';
        if (dashboard && dashboard.websites) {
            const scores = Object.values(dashboard.websites).map(w => w.security_score || 0);
            if (scores.length > 0) avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        }
        setEl('metricPosture', avgScore + '/100');

        // Scan Rate
        const scansPerHour = Math.round(3600 / 15);
        setEl('metricScanRate', scansPerHour);
    }

    /* ── Preloader Boot Sequence ── */
    function runBootSequence() {
        const preloader = $('#preloader');
        if (!preloader) return;
        setTimeout(() => {
            preloader.classList.add('hidden');
            setTimeout(() => {
                if (preloader.parentNode) preloader.style.display = 'none';
            }, 800);
        }, 3200);
    }

    /* ── Clock ── */
    function startClock() {
        const update = () => {
            const now = new Date();
            const utc = now.toISOString().substr(11, 8);
            setEl('liveClock', utc);
        };
        update();
        setInterval(update, 1000);
    }

    /* ── Initialization ── */
    function initDashboard() {
        runBootSequence();
        startClock();
        bindEvents();
        SOCData.connect();
        if (typeof SOCCharts !== 'undefined') SOCCharts.initAll();
        SOCData.onUpdate('scan', onScanData);
        SOCData.onUpdate('dashboard', onDashboardData);
        SOCData.onUpdate('events', onEventsData);
        SOCData.onUpdate('logs', onLogsData);
        SOCData.onUpdate('connection', onConnectionChange);
        updateDefconDisplay();
        updateSOCMetrics();
    }

    /* ── Event Binding ── */
    function bindEvents() {
        // Sidebar toggle
        const toggle = $('#sidebarToggle');
        if (toggle) toggle.addEventListener('click', () => {
            const sb = $('#sidebar');
            if (sb) sb.classList.toggle('collapsed');
        });
        // Mobile menu
        const mobileToggle = $('#mobileMenuToggle');
        if (mobileToggle) mobileToggle.addEventListener('click', () => {
            const sb = $('#sidebar');
            if (sb) sb.classList.toggle('mobile-open');
        });
        // Navigation
        $$('.nav-link').forEach(link => {
            link.addEventListener('click', e => {
                e.preventDefault();
                const page = link.getAttribute('data-page');
                if (page) navigateTo(page);
                const sb = $('#sidebar');
                if (sb) sb.classList.remove('mobile-open');
            });
        });
        // Scan button
        const scanBtn = $('#scanNowBtn');
        if (scanBtn) scanBtn.addEventListener('click', () => {
            SOCData.requestScan();
            showToast('Pemindaian manual dimulai...', 'info');
        });
        // Alerts button
        const alertsBtn = $('#alertsBtn');
        if (alertsBtn) alertsBtn.addEventListener('click', () => {
            const panel = $('#notificationPanel');
            if (panel) panel.classList.toggle('open');
        });
        // Notification close
        const notifClose = $('#notifClose');
        if (notifClose) notifClose.addEventListener('click', () => {
            const panel = $('#notificationPanel');
            if (panel) panel.classList.remove('open');
        });
        // Fullscreen
        const fsBtn = $('#fullscreenBtn');
        if (fsBtn) fsBtn.addEventListener('click', toggleFullscreen);
        // Alert dismiss
        const dismissBtn = $('#dismissAlert');
        if (dismissBtn) dismissBtn.addEventListener('click', () => {
            const banner = $('#alertBanner');
            if (banner) banner.classList.add('hidden');
        });
        // Website filter
        const wsFilter = $('#websiteFilter');
        if (wsFilter) wsFilter.addEventListener('change', e => {
            currentFilter = e.target.value;
            applyWebsiteFilter();
        });
    }

    function navigateTo(page) {
        $$('.page-content').forEach(p => p.classList.remove('active'));
        $$('.nav-link').forEach(l => l.classList.remove('active'));
        const pageEl = $(`#page-${page}`);
        if (pageEl) pageEl.classList.add('active');
        const navLink = $(`.nav-link[data-page="${page}"]`);
        if (navLink) navLink.classList.add('active');
        const pageNameMap = {
            'dashboard': 'pusat-komando',
            'threats': 'intelijen-ancaman',
            'incidents': 'respons-insiden',
            'network': 'monitor-jaringan',
            'logs': 'analisis-log-siem',
            'vulnerabilities': 'kerentanan',
            'endpoints': 'keamanan-endpoint',
            'firewall': 'firewall-waf',
            'assets': 'inventaris-aset',
            'compliance': 'kepatuhan-framework'
        };
        setEl('currentPage', pageNameMap[page] || page);
        // Render page specific content
        const scan = SOCData.getLatestScan();
        const dashboard = SOCData.getDashboard();
        const events = SOCData.getEvents();
        const logs = SOCData.getLogs();
        if (page === 'threats') renderThreatIntel(events);
        if (page === 'incidents') renderIncidentBoard(events);
        if (page === 'network') {
            renderNetworkPage(scan, dashboard);
            renderConnectionRadar(scan);
        }
        if (page === 'logs') renderLogViewer(logs);
        if (page === 'vulnerabilities') renderVulnerabilities(events, scan);
        if (page === 'endpoints') renderEndpoints(scan);
        if (page === 'firewall') renderFirewallRules(scan);
        if (page === 'assets') renderAssets(scan, dashboard);
        if (page === 'compliance') renderCompliance(scan, dashboard, events);
    }

    function applyWebsiteFilter() {
        if (typeof SOCCharts !== 'undefined') SOCCharts.setFilter(currentFilter);
        const scan = SOCData.getLatestScan();
        const dashboard = SOCData.getDashboard();
        const events = SOCData.getEvents();
        if (scan) onScanData(scan);
        if (dashboard) onDashboardData(dashboard);
        if (events) onEventsData(events);
    }

    function toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(() => {});
        } else {
            document.exitFullscreen().catch(() => {});
        }
    }

    /* ── Data Handlers ── */
    function onScanData(data) {
        if (!data) return;
        scanCount++;
        lastUpdateTime = Date.now();
        updateLastUpdated();
        updateAllDashboardStats(data);
        updateWebsiteCards(data);
        renderEventFeed(getFilteredEvents(SOCData.getEvents()));
        renderIncidentTable(getFilteredEvents(SOCData.getEvents()));
        renderMITREGrid();
        renderBlockedIPs(data);
        updateHealthRings(data);
        renderSecurityHeaders(data);
        renderConnectionRadar(data);
        updateSOCMetrics();
        if (typeof SOCCharts !== 'undefined') SOCCharts.updateFromScan(data, currentFilter);
    }

    function onDashboardData(data) {
        if (!data) return;
        defconLevel = calculateDefcon(data);
        infoconLevel = calculateInfocon(data);
        updateDefconDisplay();
        // Threat level display
        const tl = data.threat_level || '--';
        setEl('globalThreatLevel', tl);
        const tlEl = $('#globalThreatLevel');
        if (tlEl) {
            const upper = (tl || '').toUpperCase();
            if (upper === 'CRITICAL') { tlEl.style.color = '#ff2d55'; }
            else if (upper === 'HIGH') { tlEl.style.color = '#ff6b35'; }
            else if (upper === 'ELEVATED') { tlEl.style.color = '#f59e0b'; }
            else { tlEl.style.color = '#00ff88'; }
        }

        // Update severity counts and alert banner
        updateAlertBanner(data);
        updateTrends(data);

        // Nav badges
        if (data.total_events != null) setEl('navBadgeThreat', data.total_events);
        const events = SOCData.getEvents() || [];
        const critHigh = events.filter(e => e.severity === 'critical' || e.severity === 'high').length;
        setEl('navBadgeIncident', critHigh);
        renderNotifications(events);

        if (typeof SOCCharts !== 'undefined') SOCCharts.updateFromDashboard(data);
    }

    function onEventsData(events) {
        if (!events) return;
        const filtered = getFilteredEvents(events);
        renderEventFeed(filtered);
        renderIncidentTable(filtered);
        renderMITREGrid();
        renderNotifications(events);
    }

    function onLogsData(logs) {
        if ($('#page-logs').classList.contains('active')) {
            renderLogViewer(logs);
        }
    }

    function onConnectionChange(info) {
        const isConnected = info && info.status === 'connected';
        const dot = $('#connectionStatus');
        const label = $('.connection-label');
        if (dot) {
            dot.classList.toggle('online', isConnected);
            dot.classList.toggle('offline', !isConnected);
        }
        if (label) label.textContent = isConnected ? 'LANGSUNG' : 'TERPUTUS';
        if (!isConnected) {
            showToast('Koneksi ke server terputus', 'critical');
        } else {
            showToast('Terhubung ke backend SOC', 'success');
        }
    }

    /* ── Alert Banner ── */
    function updateAlertBanner(data) {
        const banner = $('#alertBanner');
        const msg = $('#alertMessage');
        if (!banner || !msg || !data) return;

        const tl = (data.threat_level || '').toUpperCase();
        banner.classList.remove('critical', 'warning', 'success', 'info', 'hidden');

        if (tl === 'CRITICAL') {
            banner.classList.add('critical');
            msg.innerHTML = '<strong>THREATCON 1 — KRITIS:</strong> Terdeteksi ancaman keamanan tingkat kritis. Semua operator segera eskalasi.';
        } else if (tl === 'HIGH') {
            banner.classList.add('warning');
            msg.innerHTML = '<strong>THREATCON 2 — TINGGI:</strong> Terdeteksi aktivitas ancaman tingkat tinggi. Peningkatan kewaspadaan diperlukan.';
        } else if (tl === 'ELEVATED') {
            banner.classList.add('info');
            msg.innerHTML = '<strong>THREATCON 3 — WASPADA:</strong> Aktivitas mencurigakan terdeteksi. Pemantauan ditingkatkan.';
        } else {
            banner.classList.add('success');
            msg.innerHTML = '<strong>THREATCON 5 — NORMAL:</strong> Semua sistem beroperasi normal. Tidak ada ancaman terdeteksi.';
        }
    }

    /* ── Trends ── */
    function updateTrends(data) {
        if (!data || !data.severity_counts) return;
        const sc = data.severity_counts;
        const prev = prevSeverityCounts;

        const setTrend = (id, current, previous) => {
            const el = document.getElementById(id);
            if (!el) return;
            const diff = current - (previous || 0);
            if (diff > 0) {
                el.innerHTML = `<i class="fas fa-arrow-up"></i> +${diff}`;
                el.className = 'stat-trend up';
            } else if (diff < 0) {
                el.innerHTML = `<i class="fas fa-arrow-down"></i> ${diff}`;
                el.className = 'stat-trend down';
            } else {
                el.innerHTML = `<i class="fas fa-minus"></i> 0`;
                el.className = 'stat-trend';
            }
        };

        const totalNow = (sc.critical || 0) + (sc.high || 0) + (sc.medium || 0) + (sc.low || 0);
        const totalPrev = (prev.critical || 0) + (prev.high || 0) + (prev.medium || 0) + (prev.low || 0);
        setTrend('trendThreats', totalNow, totalPrev);
        setTrend('trendIncidents', (sc.critical || 0) + (sc.high || 0), (prev.critical || 0) + (prev.high || 0));

        prevSeverityCounts = { ...sc };
    }

    /* ── Website Cards ── */
    function updateWebsiteCards(data) {
        if (!data) return;
        for (const key of getActiveKeys()) {
            const site = data[key];
            if (!site) continue;
            const prefix = key === 'himatika' ? 'him' : 'foto';
            const card = $(`#card-${key}`);
            if (!card) continue;

            const status = site.status === 'online';
            const dot = card.querySelector('.website-dot');
            const badge = card.querySelector('.website-status');
            if (dot) { dot.classList.toggle('online', status); dot.classList.toggle('offline', !status); }
            if (badge) { badge.textContent = status ? 'ONLINE' : 'OFFLINE'; badge.classList.toggle('online', status); badge.classList.toggle('offline', !status); }

            setEl(`${prefix}-uptime`, status ? '99.9%' : '0%');
            setEl(`${prefix}-response`, site.response_time_ms + 'ms');
            setEl(`${prefix}-threats`, site.security_score != null ? site.security_score + '/100' : '--');
            setEl(`${prefix}-ssl`, site.ssl && site.ssl.valid ? '✓ Valid' : '✗ Invalid');

            // Threat bar
            const bar = $(`#${prefix}-threat-bar`);
            if (bar && site.security_score != null) {
                bar.innerHTML = `<div style="width:${site.security_score}%;height:100%;background:${site.security_score > 70 ? 'var(--accent-green)' : site.security_score > 40 ? 'var(--warning)' : 'var(--critical)'};border-radius:2px;transition:width 0.5s ease;"></div>`;
            }
        }
    }

    /* ── Dashboard Stats ── */
    function updateAllDashboardStats(data) {
        if (!data) return;
        const events = SOCData.getEvents() || [];
        const filtered = getFilteredEvents(events);
        setEl('totalThreats', filtered.length);
        const critHigh = filtered.filter(e => e.severity === 'critical' || e.severity === 'high').length;
        setEl('activeIncidents', critHigh);

        // Average security score
        let avgScore = '--';
        const keys = getActiveKeys();
        const scores = keys.map(k => data[k]?.security_score).filter(s => s != null);
        if (scores.length > 0) avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        setEl('blockedAttacks', avgScore);

        const activeKeys = getActiveKeys();
        setEl('monitoredAssets', activeKeys.length);

        const warnings = filtered.filter(e => e.severity === 'medium' || e.severity === 'high').length;
        setEl('suspiciousIPs', warnings);
        setEl('totalTraffic', scanCount);
    }

    /* ── Network Page ── */
    function renderNetworkPage(scan, dashboard) {
        if (scan) {
            const h = scan.himatika;
            const f = scan.fotografi;
            setEl('netInbound', h ? h.response_time_ms + 'ms' : '--');
            setEl('netOutbound', f ? f.response_time_ms + 'ms' : '--');
            const online = [h, f].filter(s => s && s.status === 'online').length;
            setEl('netConnections', `${online}/2`);
        }
        const events = SOCData.getEvents() || [];
        const anomalies = events.filter(e => e.severity === 'critical' || e.severity === 'high').length;
        setEl('netAnomalies', anomalies);
    }

    function updateNetworkStats(data) {
        renderNetworkPage(data, SOCData.getDashboard());
    }

    /* ── Health Rings ── */
    function updateHealthRings(data) {
        if (!data) return;
        const circumference = 2 * Math.PI * 54; // ~339.29

        const setRing = (progressId, valueId, score, color) => {
            const progress = document.getElementById(progressId);
            const valueEl = document.getElementById(valueId);
            if (progress) {
                const pct = Math.max(0, Math.min(100, score || 0));
                const offset = circumference - (pct / 100) * circumference;
                progress.style.strokeDasharray = circumference;
                progress.style.strokeDashoffset = offset;
                progress.style.stroke = color;
            }
            if (valueEl) valueEl.textContent = (score || 0) + '%';
        };

        const h = data.himatika;
        const f = data.fotografi;
        setRing('healthCPU', 'healthValHim', h?.security_score, '#00ff88');
        setRing('healthRAM', 'healthValFoto', f?.security_score, '#a855f7');

        // SSL health
        const sslValid = [h, f].filter(s => s?.ssl?.valid).length;
        const sslPct = Math.round((sslValid / 2) * 100);
        setRing('healthDisk', 'healthValSSL', sslPct, '#00d4ff');

        // Overall
        const scores = [h?.security_score || 0, f?.security_score || 0];
        const overall = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        setRing('healthNetwork', 'healthValOverall', overall, '#f59e0b');
    }

    /* ── Vulnerability Summary ── */
    function updateVulnSummary(events) {
        if (!events) return;
        let crit = 0, high = 0, med = 0, low = 0, info = 0;
        events.forEach(e => {
            switch (e.severity) {
                case 'critical': crit++; break;
                case 'high': high++; break;
                case 'medium': med++; break;
                case 'low': low++; break;
                default: info++;
            }
        });
        setEl('vulnCritical', crit);
        setEl('vulnHigh', high);
        setEl('vulnMedium', med);
        setEl('vulnLow', low);
        setEl('vulnInfo', info);
        setEl('navBadgeVuln', crit + high);
    }

    /* ── Security Headers Display ── */
    function renderSecurityHeaders(data) {
        const container = $('#attackOrigins');
        if (!container || !data) return;
        let html = '';
        const keys = getActiveKeys();
        keys.forEach(key => {
            const site = data[key];
            if (!site || !site.security_headers) return;
            html += `<div style="margin-bottom:0.75rem;">
                <div style="font-family:var(--font-mono);font-size:0.7rem;font-weight:700;color:var(--accent-cyan);margin-bottom:0.3rem;">
                    ${sanitize(SOCData.websites[key]?.name || key)}
                </div>`;
            for (const [header, info] of Object.entries(site.security_headers)) {
                const icon = info.present ? 'fa-check-circle' : 'fa-times-circle';
                const color = info.present ? 'var(--accent-green)' : 'var(--critical)';
                html += `<div style="display:flex;align-items:center;gap:0.4rem;font-size:0.65rem;padding:0.15rem 0;">
                    <i class="fas ${icon}" style="color:${color};font-size:0.55rem;"></i>
                    <span style="color:var(--text-secondary);">${sanitize(header)}</span>
                </div>`;
            }
            html += '</div>';
        });
        container.innerHTML = html || '<div style="color:var(--text-dim);font-size:0.75rem;padding:1rem;text-align:center;">Menunggu data pemindaian...</div>';
    }

    /* ── Event Feed ── */
    function renderEventFeed(events) {
        const feed = $('#eventFeed');
        if (!feed) return;
        if (!events || events.length === 0) {
            feed.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:2rem;text-align:center;">Menunggu peristiwa keamanan...</div>';
            return;
        }
        const latest = events.slice(-50).reverse();
        feed.innerHTML = latest.map(e => {
            const sev = e.severity || 'info';
            const sevColors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--warning)', low: 'var(--accent-green)', info: 'var(--info)' };
            const sevBg = { critical: 'rgba(255,45,85,0.15)', high: 'rgba(255,107,53,0.15)', medium: 'rgba(245,158,11,0.15)', low: 'rgba(0,255,136,0.15)', info: 'rgba(0,212,255,0.15)' };
            return `<div class="event-item severity-${sev}">
                <span class="event-time">${SOCData.formatTime(e.timestamp)}</span>
                <span class="event-severity" style="background:${sevBg[sev] || sevBg.info};color:${sevColors[sev] || sevColors.info};">${sev.toUpperCase()}</span>
                <span class="event-message">${sanitize(e.title || e.description || '--')}</span>
            </div>`;
        }).join('');
    }

    /* ── Incident Table ── */
    function renderIncidentTable(events) {
        const tbody = $('#incidentTableBody');
        if (!tbody) return;
        if (!events || events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:2rem;">Tidak ada insiden terdeteksi</td></tr>';
            return;
        }
        const latest = events.slice(-25).reverse();
        tbody.innerHTML = latest.map((e, i) => {
            const sev = e.severity || 'info';
            const id = e.id || `INC-${String(Date.now()).slice(-6)}-${String(i + 1).padStart(3, '0')}`;
            const disposition = sev === 'critical' ? 'Eskalasi' : sev === 'high' ? 'Investigasi' : 'Triage';
            const dispColor = sev === 'critical' ? 'rgba(255,45,85,0.15);color:var(--critical)' : sev === 'high' ? 'rgba(245,158,11,0.15);color:var(--warning)' : 'rgba(0,212,255,0.15);color:var(--info)';
            return `<tr>
                <td><span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--accent-cyan);">${sanitize(id)}</span></td>
                <td><span style="font-family:var(--font-mono);font-size:0.65rem;">${SOCData.formatTime(e.timestamp)}</span></td>
                <td>${sanitize(e.site_name || e.site_key || '--')}</td>
                <td>${sanitize(e.title || '--')}</td>
                <td>${sanitize(e.category || 'Network')}</td>
                <td><span class="severity-badge ${sev}">${sev.toUpperCase()}</span></td>
                <td><span class="disposition-badge" style="background:${dispColor}">${disposition}</span></td>
                <td><button class="table-action-btn" onclick="SOCApp.investigateIncident('${sanitize(id)}')"><i class="fas fa-search"></i> Detail</button></td>
            </tr>`;
        }).join('');
    }

    /* ── MITRE ATT&CK Grid ── */
    function renderMITREGrid() {
        const grid = $('#mitreGrid');
        if (!grid) return;
        const techniques = SOCData.mitreAttack || [];
        grid.innerHTML = techniques.map(t => {
            const isActive = t.count > 0;
            const color = isActive ? (t.count >= 5 ? 'var(--critical)' : t.count >= 2 ? 'var(--warning)' : 'var(--accent-cyan)') : 'var(--text-dim)';
            return `<div class="mitre-item ${isActive ? 'active' : ''}">
                <span class="mitre-id">${sanitize(t.id)}</span>
                <span class="mitre-name">${sanitize(t.name)}</span>
                <span class="mitre-count" style="color:${color};">${t.count || 0}</span>
            </div>`;
        }).join('');
    }

    /* ── Blocked IPs ── */
    function renderBlockedIPs(data) {
        const container = $('#blockedIPsList');
        if (!container || !data) return;
        let ips = [];
        const keys = getActiveKeys();
        keys.forEach(key => {
            const site = data[key];
            if (site && site.dns) {
                (site.dns.a_records || []).forEach(ip => {
                    ips.push({ ip, website: SOCData.websites[key]?.name || key, type: 'A Record' });
                });
            }
        });
        if (ips.length === 0) {
            container.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:1rem;text-align:center;">Menunggu data DNS...</div>';
            return;
        }
        container.innerHTML = ips.map(item =>
            `<div class="blocked-ip-item">
                <span class="ip-address">${sanitize(item.ip)}</span>
                <span class="ip-reason">${sanitize(item.website)} — ${sanitize(item.type)}</span>
            </div>`
        ).join('');
        setEl('ipsBlacklisted', ips.length);
    }

    /* ── Notifications ── */
    function renderNotifications(events) {
        const list = $('#notifList');
        const badge = $('#notifBadge');
        if (!list) return;
        if (!events || events.length === 0) {
            list.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:2rem;text-align:center;">Tidak ada notifikasi</div>';
            if (badge) badge.textContent = '0';
            return;
        }
        const important = events.filter(e => e.severity === 'critical' || e.severity === 'high').slice(-20).reverse();
        if (badge) badge.textContent = important.length;
        list.innerHTML = important.map(e => {
            const sev = e.severity || 'info';
            return `<div class="notif-item severity-${sev}">
                <div style="display:flex;justify-content:space-between;margin-bottom:0.25rem;">
                    <span class="severity-badge ${e.severity}">${(e.severity || '').toUpperCase()}</span>
                    <span style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-dim);">${SOCData.formatTime(e.timestamp)}</span>
                </div>
                <div style="font-size:0.75rem;color:var(--text-secondary);">${sanitize(e.title || e.description)}</div>
                <div style="font-size:0.6rem;color:var(--text-dim);margin-top:0.2rem;">${sanitize(e.site_name || '--')}</div>
            </div>`;
        }).join('');
    }

    /* ── Connection Radar with Global Attack Sources ── */
    function renderConnectionRadar(data) {
        if (!data) return;
        const overlay = $('#mapOverlay');
        if (!overlay) return;

        // Target position (Indonesia)
        const targetX = 74; // %
        const targetY = 49.6; // %

        const attackSources = [
            { name: 'AS — USA', x: 18, y: 25 },
            { name: 'EU — Jerman', x: 49, y: 16 },
            { name: 'CN — Tiongkok', x: 73, y: 22 },
            { name: 'RU — Rusia', x: 60, y: 12 },
            { name: 'BR — Brasil', x: 24, y: 58 },
            { name: 'IN — India', x: 63, y: 35 },
            { name: 'JP — Jepang', x: 81, y: 20 },
            { name: 'AU — Australia', x: 83, y: 70 },
            { name: 'KR — Korea', x: 79, y: 24 },
            { name: 'NG — Nigeria', x: 47, y: 42 }
        ];

        const events = getFilteredEvents(SOCData.getEvents()) || [];
        const hasThreats = events.length > 0;

        let html = '';
        if (hasThreats) {
            attackSources.forEach((src, i) => {
                const active = Math.random() > 0.3;
                if (!active) return;
                const dx = targetX - src.x;
                const dy = targetY - src.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                const angle = Math.atan2(dy, dx) * (180 / Math.PI);

                html += `<div class="attack-dot" style="left:${src.x}%;top:${src.y}%;animation-delay:${i * 0.3}s;" title="${src.name}"></div>`;
                html += `<div class="attack-line" style="left:${src.x}%;top:${src.y}%;width:${distance}%;transform:rotate(${angle}deg);animation-delay:${i * 0.5}s;"></div>`;
            });
        }
        overlay.innerHTML = html;
        setEl('liveAttacks', hasThreats ? Math.floor(Math.random() * 15) + events.length : 0);
        setEl('countriesBlocked', hasThreats ? attackSources.length : 0);
    }

    /* ── Incident Board (Kanban) ── */
    function renderIncidentBoard(events) {
        const newCol = $('#incidentsNew');
        const invCol = $('#incidentsInvestigating');
        const conCol = $('#incidentsContainment');
        const resCol = $('#incidentsResolved');
        if (!newCol) return;

        if (!events || events.length === 0) {
            [newCol, invCol, conCol, resCol].forEach(c => {
                if (c) c.innerHTML = '<div style="color:var(--text-dim);font-size:0.7rem;padding:1rem;text-align:center;">Kosong</div>';
            });
            return;
        }

        const critical = events.filter(e => e.severity === 'critical');
        const high = events.filter(e => e.severity === 'high');
        const medium = events.filter(e => e.severity === 'medium');
        const low = events.filter(e => e.severity === 'low' || e.severity === 'info');

        const renderCards = (items) => items.slice(-8).reverse().map(e => `
            <div class="incident-card" style="border-left-color:${e.severity === 'critical' ? 'var(--critical)' : e.severity === 'high' ? 'var(--high)' : e.severity === 'medium' ? 'var(--warning)' : 'var(--accent-green)'};">
                <div class="incident-card-title">${sanitize(e.title || e.description || '--')}</div>
                <div class="incident-card-meta">${sanitize(e.site_name || '--')} · ${SOCData.formatTime(e.timestamp)} · <span class="severity-badge ${e.severity || 'info'}">${(e.severity || 'info').toUpperCase()}</span></div>
            </div>
        `).join('');

        newCol.innerHTML = renderCards(critical) || '<div style="color:var(--text-dim);font-size:0.7rem;padding:1rem;text-align:center;">Kosong</div>';
        invCol.innerHTML = renderCards(high) || '<div style="color:var(--text-dim);font-size:0.7rem;padding:1rem;text-align:center;">Kosong</div>';
        conCol.innerHTML = renderCards(medium) || '<div style="color:var(--text-dim);font-size:0.7rem;padding:1rem;text-align:center;">Kosong</div>';
        resCol.innerHTML = renderCards(low) || '<div style="color:var(--text-dim);font-size:0.7rem;padding:1rem;text-align:center;">Kosong</div>';

        setEl('countNew', critical.length);
        setEl('countInvestigating', high.length);
        setEl('countContainment', medium.length);
        setEl('countResolved', low.length);
    }

    /* ── Log Viewer ── */
    function renderLogViewer(logs) {
        const viewer = $('#logViewer');
        if (!viewer) return;
        if (!logs || logs.length === 0) {
            viewer.innerHTML = '<div style="color:var(--text-dim);padding:2rem;text-align:center;">Menunggu log masuk...</div>';
            return;
        }
        const search = ($('#logSearch') || {}).value || '';
        const levelFilter = ($('#logLevel') || {}).value || 'all';

        let filtered = logs;
        if (search) {
            const q = search.toLowerCase();
            filtered = filtered.filter(l => (l.message || '').toLowerCase().includes(q) || (l.source || '').toLowerCase().includes(q));
        }
        if (levelFilter !== 'all') {
            filtered = filtered.filter(l => (l.level || '').toLowerCase() === levelFilter);
        }

        viewer.innerHTML = filtered.slice(-200).reverse().map(l => {
            const level = (l.level || 'info').toLowerCase();
            const levelColors = { critical: 'var(--critical)', error: 'var(--high)', warning: 'var(--warning)', info: 'var(--info)' };
            return `<div class="log-entry level-${level}">
                <span class="log-time">${SOCData.formatTime(l.timestamp)}</span>
                <span class="log-level-badge" style="color:${levelColors[level] || levelColors.info};">[${(l.level || 'INFO').toUpperCase()}]</span>
                <span class="log-source">${sanitize(l.source || 'system')}</span>
                <span class="log-message">${sanitize(l.message || '--')}</span>
            </div>`;
        }).join('');
    }

    /* ── Threat Intel Page ── */
    function renderThreatIntel(events) {
        if (!events) events = [];
        const malware = $('#malwareCampaigns');
        const ioc = $('#iocIndicators');
        const apt = $('#aptGroups');
        const feed = $('#threatFeed');

        const campaigns = [
            { name: 'WebShell Injector v3', type: 'Trojan', status: 'Aktif', level: 'critical' },
            { name: 'SQLi Automated Scanner', type: 'Scanner', status: 'Terdeteksi', level: 'high' },
            { name: 'XSS Payload Distributor', type: 'Exploit Kit', status: 'Dipantau', level: 'medium' }
        ];
        if (malware) {
            malware.innerHTML = campaigns.map(c => `
                <div class="intel-item">
                    <span class="severity-badge ${c.level}">${c.level.toUpperCase()}</span>
                    <div style="flex:1;">
                        <div style="font-weight:600;font-size:0.75rem;">${c.name}</div>
                        <div style="font-size:0.6rem;color:var(--text-dim);">${c.type} · ${c.status}</div>
                    </div>
                </div>
            `).join('');
        }

        const iocList = [
            { type: 'IP', value: '185.220.101.x', source: 'Threat Feed' },
            { type: 'Hash', value: 'a1b2c3d4...', source: 'VirusTotal' },
            { type: 'Domain', value: 'malicious-scanner.xyz', source: 'Internal' },
            { type: 'URL', value: '/wp-admin/exploit.php', source: 'WAF Log' }
        ];
        if (ioc) {
            ioc.innerHTML = iocList.map(i => `
                <div class="intel-item">
                    <span style="font-family:var(--font-mono);font-size:0.6rem;color:var(--accent-purple);min-width:45px;">${i.type}</span>
                    <span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--accent-cyan);flex:1;">${i.value}</span>
                    <span style="font-size:0.6rem;color:var(--text-dim);">${i.source}</span>
                </div>
            `).join('');
        }

        const aptList = [
            { name: 'APT-28 (Fancy Bear)', origin: 'Rusia', activity: 'Reconnaissance', level: 'high' },
            { name: 'Lazarus Group', origin: 'Korea Utara', activity: 'Dormant', level: 'medium' },
            { name: 'APT-41 (Double Dragon)', origin: 'Tiongkok', activity: 'Active Scanning', level: 'critical' }
        ];
        if (apt) {
            apt.innerHTML = aptList.map(a => `
                <div class="intel-item">
                    <span class="severity-badge ${a.level}">${a.level.toUpperCase()}</span>
                    <div style="flex:1;">
                        <div style="font-weight:600;font-size:0.75rem;">${a.name}</div>
                        <div style="font-size:0.6rem;color:var(--text-dim);">${a.origin} · ${a.activity}</div>
                    </div>
                </div>
            `).join('');
        }

        if (feed) {
            const critical = events.filter(e => e.severity === 'critical' || e.severity === 'high').slice(-10).reverse();
            if (critical.length === 0) {
                feed.innerHTML = '<div style="color:var(--text-dim);padding:1rem;text-align:center;">Tidak ada ancaman tinggi terbaru</div>';
            } else {
                feed.innerHTML = critical.map(e => `
                    <div class="intel-item">
                        <span class="severity-badge ${e.severity}">${(e.severity || '').toUpperCase()}</span>
                        <div style="flex:1;">
                            <div style="font-size:0.75rem;">${sanitize(e.title || e.description || '--')}</div>
                            <div style="font-size:0.6rem;color:var(--text-dim);">${sanitize(e.site_name || '--')} · ${SOCData.formatTime(e.timestamp)}</div>
                        </div>
                    </div>
                `).join('');
            }
        }
    }

    /* ── Vulnerabilities Page ── */
    function renderVulnerabilities(events, scan) {
        updateVulnSummary(events);
        const list = $('#vulnList');
        if (!list || !events) return;

        const vulnEvents = events.filter(e => e.severity === 'critical' || e.severity === 'high' || e.title?.includes('header') || e.title?.includes('Header'));
        if (vulnEvents.length === 0) {
            list.innerHTML = '<div style="color:var(--text-dim);padding:2rem;text-align:center;">Tidak ada kerentanan terdeteksi</div>';
            return;
        }
        list.innerHTML = vulnEvents.slice(-20).reverse().map(e => {
            const sev = e.severity || 'info';
            const borderColor = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--warning)', low: 'var(--accent-green)' };
            return `<div class="vuln-item" style="border-left-color:${borderColor[sev] || 'var(--info)'};">
                <span class="severity-badge ${sev}">${sev.toUpperCase()}</span>
                <div style="flex:1;">
                    <div style="font-weight:600;font-size:0.8rem;">${sanitize(e.title || '--')}</div>
                    <div style="font-size:0.7rem;color:var(--text-secondary);">${sanitize(e.description || '--')}</div>
                </div>
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-dim);">${sanitize(e.site_name || '--')}</div>
            </div>`;
        }).join('');
    }

    /* ── Endpoints Page ── */
    function renderEndpoints(scan) {
        const grid = $('#endpointGrid');
        if (!grid) return;
        const keys = getActiveKeys();
        if (!scan) { grid.innerHTML = '<div style="color:var(--text-dim);padding:2rem;text-align:center;">Menunggu data...</div>'; return; }

        grid.innerHTML = keys.map(key => {
            const site = scan[key];
            if (!site) return '';
            const online = site.status === 'online';
            const ws = SOCData.websites[key] || {};
            return `<div class="endpoint-card">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
                    <h4 style="font-family:var(--font-mono);font-size:0.8rem;color:${ws.color || 'var(--accent-cyan)'};">${sanitize(ws.name || key)}</h4>
                    <span class="severity-badge ${online ? 'low' : 'critical'}">${online ? 'ONLINE' : 'OFFLINE'}</span>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;font-size:0.7rem;">
                    <div><span style="color:var(--text-dim);">Respons:</span> <span style="font-family:var(--font-mono);">${site.response_time_ms + 'ms'}</span></div>
                    <div><span style="color:var(--text-dim);">SSL:</span> <span style="font-family:var(--font-mono);">${site.ssl?.valid ? '✓ Valid' : '✗ Invalid'}</span></div>
                    <div><span style="color:var(--text-dim);">Skor:</span> <span style="font-family:var(--font-mono);">${site.security_score || '--'}/100</span></div>
                    <div><span style="color:var(--text-dim);">IP:</span> <span style="font-family:var(--font-mono);">${site.dns?.a_records?.[0] || '--'}</span></div>
                </div>
            </div>`;
        }).join('');
    }

    /* ── Firewall Rules Page ── */
    function renderFirewallRules(scan) {
        const container = $('#firewallRules');
        if (!container) return;
        const rules = [
            { action: 'ALLOW', proto: 'HTTPS', port: '443', source: '*', dest: 'himatika/fotografi', desc: 'Izinkan lalu lintas HTTPS' },
            { action: 'ALLOW', proto: 'HTTP', port: '80', source: '*', dest: 'himatika/fotografi', desc: 'Izinkan lalu lintas HTTP (redirect)' },
            { action: 'DENY', proto: 'TCP', port: '22', source: 'External', dest: 'All', desc: 'Blokir akses SSH dari luar' },
            { action: 'DENY', proto: 'TCP', port: '3306', source: 'External', dest: 'All', desc: 'Blokir akses database langsung' },
            { action: 'ALLOW', proto: 'DNS', port: '53', source: '*', dest: 'DNS Server', desc: 'Izinkan resolusi DNS' },
            { action: 'DENY', proto: 'ICMP', port: '*', source: 'External', dest: 'All', desc: 'Blokir ping dari luar' }
        ];
        container.innerHTML = rules.map(r => `
            <div class="fw-rule">
                <span class="fw-rule-action ${r.action.toLowerCase()}">${r.action}</span>
                <span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--accent-cyan);min-width:50px;">${r.proto}</span>
                <span style="font-family:var(--font-mono);font-size:0.7rem;min-width:40px;">:${r.port}</span>
                <span style="font-size:0.7rem;color:var(--text-secondary);flex:1;">${r.source} → ${r.dest}</span>
                <span style="font-size:0.65rem;color:var(--text-dim);">${r.desc}</span>
            </div>
        `).join('');
    }

    /* ── Assets Page ── */
    function renderAssets(scan, dashboard) {
        const grid = $('#assetGrid');
        if (!grid) return;
        const assets = [
            { name: 'himatikafmipaunhas.id', type: 'Web Server', os: 'Linux', status: 'online', icon: 'fa-globe' },
            { name: 'ukmfotografiunhas.com', type: 'Web Server', os: 'Linux', status: 'online', icon: 'fa-camera' },
            { name: 'DNS Primary', type: 'DNS Server', os: 'Cloudflare', status: 'online', icon: 'fa-server' },
            { name: 'SSL/TLS Cert', type: 'Certificate', os: "Let's Encrypt", status: 'online', icon: 'fa-lock' },
            { name: 'WAF Engine', type: 'Security', os: 'ModSecurity', status: 'active', icon: 'fa-shield-halved' },
            { name: 'SOC Backend', type: 'Monitor', os: 'Python/Flask', status: 'online', icon: 'fa-terminal' },
            { name: 'IDS/IPS Module', type: 'Security', os: 'Custom', status: 'active', icon: 'fa-eye' },
            { name: 'Log Aggregator', type: 'SIEM', os: 'Custom', status: 'online', icon: 'fa-database' }
        ];
        grid.innerHTML = assets.map(a => `
            <div class="asset-card">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">
                    <i class="fas ${a.icon}" style="color:var(--accent-cyan);"></i>
                    <span style="font-family:var(--font-mono);font-size:0.8rem;font-weight:600;">${a.name}</span>
                </div>
                <div style="font-size:0.7rem;color:var(--text-secondary);margin-bottom:0.25rem;">Tipe: ${a.type}</div>
                <div style="font-size:0.7rem;color:var(--text-secondary);margin-bottom:0.25rem;">Platform: ${a.os}</div>
                <span class="severity-badge low">${a.status.toUpperCase()}</span>
            </div>
        `).join('');
    }

    /* ── Compliance Page ── */
    function renderCompliance(scan, dashboard, events) {
        renderNISTCSF();
        renderOWASP();
        renderHeaderCompliance(scan);
    }

    function renderNISTCSF() {
        const grid = $('#nistGrid');
        if (!grid) return;
        const functions = [
            { id: 'GV', name: 'GOVERN', css: 'govern', icon: 'fa-landmark', items: [
                { name: 'Kebijakan Keamanan Siber', status: 'check' },
                { name: 'Manajemen Risiko', status: 'check' },
                { name: 'Peran & Tanggung Jawab', status: 'check' }
            ]},
            { id: 'ID', name: 'IDENTIFY', css: 'identify', icon: 'fa-magnifying-glass', items: [
                { name: 'Inventaris Aset (AM)', status: 'check' },
                { name: 'Penilaian Risiko (RA)', status: 'check' },
                { name: 'Lingkungan Bisnis (BE)', status: 'minus' }
            ]},
            { id: 'PR', name: 'PROTECT', css: 'protect', icon: 'fa-shield-halved', items: [
                { name: 'Kontrol Akses (AC)', status: 'check' },
                { name: 'Keamanan Data (DS)', status: 'check' },
                { name: 'Teknologi Pelindung (PT)', status: 'check' }
            ]},
            { id: 'DE', name: 'DETECT', css: 'detect', icon: 'fa-radar', items: [
                { name: 'Monitoring Berkelanjutan (CM)', status: 'check' },
                { name: 'Proses Deteksi (DP)', status: 'check' },
                { name: 'Deteksi Anomali (AE)', status: 'check' }
            ]},
            { id: 'RS', name: 'RESPOND', css: 'respond', icon: 'fa-bolt', items: [
                { name: 'Perencanaan Respons (RP)', status: 'check' },
                { name: 'Komunikasi (CO)', status: 'minus' },
                { name: 'Analisis (AN)', status: 'check' }
            ]},
            { id: 'RC', name: 'RECOVER', css: 'recover', icon: 'fa-rotate', items: [
                { name: 'Perencanaan Pemulihan (RP)', status: 'minus' },
                { name: 'Peningkatan (IM)', status: 'check' },
                { name: 'Komunikasi (CO)', status: 'times' }
            ]}
        ];
        grid.innerHTML = functions.map(f => `
            <div class="nist-card ${f.css}">
                <div class="nist-card-title"><i class="fas ${f.icon}" style="color:var(--accent-cyan);"></i> ${f.id} — ${f.name}</div>
                <div class="nist-card-items">
                    ${f.items.map(i => `<div class="nist-sub-item"><i class="fas fa-${i.status}-circle"></i> ${i.name}</div>`).join('')}
                </div>
            </div>
        `).join('');
    }

    function renderOWASP() {
        const grid = $('#owaspGrid');
        if (!grid) return;
        const items = [
            { id: 'A01', name: 'Broken Access Control', desc: 'Pemantauan header keamanan dan akses kontrol' },
            { id: 'A02', name: 'Cryptographic Failures', desc: 'Validasi SSL/TLS dan enkripsi data' },
            { id: 'A03', name: 'Injection', desc: 'Deteksi SQL injection, XSS, command injection' },
            { id: 'A04', name: 'Insecure Design', desc: 'Review arsitektur keamanan' },
            { id: 'A05', name: 'Security Misconfiguration', desc: 'Pemeriksaan konfigurasi header keamanan' },
            { id: 'A06', name: 'Vulnerable Components', desc: 'Pemindaian komponen rentan' },
            { id: 'A07', name: 'Auth Failures', desc: 'Validasi mekanisme autentikasi' },
            { id: 'A08', name: 'Data Integrity Failures', desc: 'Deteksi perubahan konten tidak sah' },
            { id: 'A09', name: 'Logging Failures', desc: 'Sistem logging SIEM terpusat' },
            { id: 'A10', name: 'SSRF', desc: 'Perlindungan terhadap SSRF' }
        ];
        grid.innerHTML = items.map(i => `
            <div class="owasp-item">
                <div class="owasp-item-title">${i.id}: ${i.name}</div>
                <div class="owasp-item-desc">${i.desc}</div>
            </div>
        `).join('');
    }

    function renderHeaderCompliance(scan) {
        const grid = $('#complianceGrid');
        if (!grid || !scan) return;
        const keys = getActiveKeys();
        grid.innerHTML = keys.map(key => {
            const site = scan[key];
            if (!site || !site.security_headers) return '';
            return `<div class="header-site-section">
                <div class="header-site-title">${sanitize(SOCData.websites[key]?.name || key)}</div>
                ${Object.entries(site.security_headers).map(([header, info]) => {
                    const icon = info.present ? 'fa-check-circle' : 'fa-times-circle';
                    return `<div class="header-check"><i class="fas ${icon}"></i> ${sanitize(header)}</div>`;
                }).join('')}
            </div>`;
        }).join('');
    }

    /* ── Toast ── */
    function showToast(message, type = 'info') {
        const container = $('#toastContainer');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        const icons = { critical: 'fa-skull', warning: 'fa-triangle-exclamation', success: 'fa-check-circle', info: 'fa-info-circle' };
        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.info}"></i>
            <span>${sanitize(message)}</span>
            <button class="toast-close" onclick="this.parentElement.remove()"><i class="fas fa-xmark"></i></button>
        `;
        container.appendChild(toast);
        setTimeout(() => { if (toast.parentNode) toast.remove(); }, 5000);
    }

    /* ── Last Updated ── */
    function updateLastUpdated() {
        const el = $('#lastUpdated');
        if (!el || !lastUpdateTime) return;
        const update = () => {
            const diff = Math.floor((Date.now() - lastUpdateTime) / 1000);
            el.textContent = diff < 5 ? 'Baru saja' : diff + 'd lalu';
        };
        update();
        clearInterval(window._lastUpdatedInterval);
        window._lastUpdatedInterval = setInterval(update, 1000);
    }

    function investigateIncident(id) {
        showToast(`Membuka investigasi insiden ${id}...`, 'info');
    }

    /* ── Expose API ── */
    window.SOCApp = { investigateIncident, showToast, navigateTo };

    /* ── Start ── */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDashboard);
    } else {
        initDashboard();
    }
})();
