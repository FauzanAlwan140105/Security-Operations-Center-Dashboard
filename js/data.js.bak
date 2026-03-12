const SOCData = (() => {
    'use strict';

    let socket = null;
    let connected = false;
    const API_BASE = window.location.origin;

    let latestScan = {};
    let dashboardData = {};
    let liveEvents = [];
    let liveLogs = [];
    let scanHistory = { himatika: [], fotografi: [] };

    const callbacks = {
        scan: [],
        dashboard: [],
        events: [],
        logs: [],
        connection: []
    };

    function connect() {
        if (typeof io === 'undefined') {
            startPolling();
            return;
        }

        socket = io(API_BASE, {
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: 2000,
            reconnectionAttempts: 50
        });

        socket.on('connect', () => {
            connected = true;
            _fireCallbacks('connection', { status: 'connected' });
        });

        socket.on('disconnect', () => {
            connected = false;
            _fireCallbacks('connection', { status: 'disconnected' });
        });

        socket.on('connect_error', () => {
            connected = false;
        });

        socket.on('scan_complete', (data) => {
            latestScan = data;
            _updateScanHistory(data);
            _fireCallbacks('scan', data);
        });

        socket.on('dashboard_update', (data) => {
            dashboardData = data;
            _fireCallbacks('dashboard', data);
        });

        socket.on('events_update', (data) => {
            liveEvents = data;
            _fireCallbacks('events', data);
        });

        socket.on('logs_update', (data) => {
            liveLogs = data;
            _fireCallbacks('logs', data);
        });
    }

    let pollTimer = null;

    function startPolling() {
        pollOnce();
        pollTimer = setInterval(pollOnce, 8000);
    }

    async function pollOnce() {
        try {
            const [dashRes, evtRes, logRes, statusRes] = await Promise.all([
                fetchAPI('/api/dashboard'),
                fetchAPI('/api/events'),
                fetchAPI('/api/logs'),
                fetchAPI('/api/status')
            ]);

            if (statusRes) {
                latestScan = statusRes;
                _updateScanHistory(statusRes);
                _fireCallbacks('scan', statusRes);
            }
            if (dashRes) {
                dashboardData = dashRes;
                _fireCallbacks('dashboard', dashRes);
            }
            if (evtRes) {
                liveEvents = evtRes;
                _fireCallbacks('events', evtRes);
            }
            if (logRes) {
                liveLogs = logRes;
                _fireCallbacks('logs', logRes);
            }
        } catch (e) {
            /* polling error */
        }
    }

    async function fetchAPI(endpoint) {
        try {
            const resp = await fetch(API_BASE + endpoint);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            return await resp.json();
        } catch (e) {
            return null;
        }
    }

    function requestScan() {
        if (socket && connected) {
            socket.emit('request_scan');
        } else {
            fetchAPI('/api/scan');
        }
    }

    function _updateScanHistory(data) {
        for (const key of ['himatika', 'fotografi']) {
            if (data[key]) {
                scanHistory[key].push({
                    timestamp: data[key].timestamp,
                    response_time_ms: data[key].response_time_ms,
                    status: data[key].status,
                    status_code: data[key].status_code,
                    security_score: data[key].security_score
                });
                if (scanHistory[key].length > 500) scanHistory[key].shift();
            }
        }
    }

    function onUpdate(type, callback) {
        if (callbacks[type]) {
            callbacks[type].push(callback);
        }
    }

    function _fireCallbacks(type, data) {
        if (callbacks[type]) {
            callbacks[type].forEach(cb => {
                try { cb(data); } catch (e) { /* callback error */ }
            });
        }
    }

    function getLatestScan() { return latestScan; }
    function getDashboard() { return dashboardData; }
    function getEvents() { return liveEvents; }
    function getLogs() { return liveLogs; }
    function getHistory(siteKey) { return scanHistory[siteKey] || []; }
    function isConnected() { return connected; }

    function randomBetween(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function formatTime(isoStr) {
        if (!isoStr) return '--:--:--';
        const d = new Date(isoStr);
        return d.toLocaleTimeString('en-GB', { hour12: false });
    }

    function timeSince(isoStr) {
        if (!isoStr) return 'N/A';
        const secs = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000);
        if (secs < 60) return `${secs}s ago`;
        if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
        return `${Math.floor(secs / 3600)}h ago`;
    }

    const websites = {
        himatika: { name: 'himatikafmipaunhas', color: '#00d4ff' },
        fotografi: { name: 'ukmfotografiunhas.com', color: '#a855f7' }
    };

    const mitreAttack = [
        { id: 'T1190', name: 'Exploit Public-Facing App', count: 0, level: 'low' },
        { id: 'T1071', name: 'Application Layer Protocol', count: 0, level: 'low' },
        { id: 'T1595', name: 'Active Scanning', count: 0, level: 'low' },
        { id: 'T1592', name: 'Gather Victim Host Info', count: 0, level: 'low' },
        { id: 'T1590', name: 'Gather Victim Network Info', count: 0, level: 'low' },
        { id: 'T1589', name: 'Gather Victim Identity', count: 0, level: 'low' },
        { id: 'T1498', name: 'Network DoS', count: 0, level: 'low' },
        { id: 'T1557', name: 'Adversary-in-the-Middle', count: 0, level: 'low' },
        { id: 'T1040', name: 'Network Sniffing', count: 0, level: 'low' },
        { id: 'T1588', name: 'Obtain Capabilities', count: 0, level: 'low' }
    ];

    function updateMITREFromEvents(events) {
        mitreAttack.forEach(m => { m.count = 0; m.level = 'low'; });

        events.forEach(ev => {
            const title = (ev.title || '').toLowerCase();
            if (title.includes('hsts') || title.includes('downgrade')) {
                const item = mitreAttack.find(m => m.id === 'T1557');
                if (item) item.count++;
            }
            if (title.includes('csp') || title.includes('xss')) {
                const item = mitreAttack.find(m => m.id === 'T1190');
                if (item) item.count++;
            }
            if (title.includes('frame') || title.includes('clickjack')) {
                const item = mitreAttack.find(m => m.id === 'T1190');
                if (item) item.count++;
            }
            if (title.includes('ssl') || title.includes('certificate')) {
                const item = mitreAttack.find(m => m.id === 'T1040');
                if (item) item.count++;
            }
            if (title.includes('scan') || title.includes('active')) {
                const item = mitreAttack.find(m => m.id === 'T1595');
                if (item) item.count++;
            }
            if (title.includes('unreachable') || title.includes('offline')) {
                const item = mitreAttack.find(m => m.id === 'T1498');
                if (item) item.count++;
            }
            if (title.includes('security score')) {
                const item = mitreAttack.find(m => m.id === 'T1592');
                if (item) item.count++;
            }
            if (title.includes('content change')) {
                const item = mitreAttack.find(m => m.id === 'T1071');
                if (item) item.count++;
            }
        });

        mitreAttack.forEach(m => {
            if (m.count >= 5) m.level = 'high';
            else if (m.count >= 2) m.level = 'med';
            else m.level = 'low';
        });
    }

    return {
        connect,
        requestScan,
        onUpdate,
        getLatestScan,
        getDashboard,
        getEvents,
        getLogs,
        getHistory,
        isConnected,
        randomBetween,
        formatTime,
        timeSince,
        websites,
        mitreAttack,
        updateMITREFromEvents,
        fetchAPI
    };
})();
