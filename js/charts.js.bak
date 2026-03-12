const SOCCharts = (() => {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(30, 41, 59, 0.5)';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.padding = 16;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 10;

    const chartInstances = {};

    const tooltipStyle = {
        backgroundColor: '#111927',
        borderColor: '#1e293b',
        borderWidth: 1,
        titleFont: { weight: '600' },
        padding: 12,
        cornerRadius: 8
    };

    function createThreatTimeline() {
        const ctx = document.getElementById('threatTimeline');
        if (!ctx) return;

        chartInstances.threatTimeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'himatikafmipaunhas (md)',
                        data: [],
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.08)',
                        borderWidth: 2, fill: true, tension: 0.4,
                        pointRadius: 2, pointHoverRadius: 5,
                        pointHoverBackgroundColor: '#00d4ff'
                    },
                    {
                        label: 'ukmfotografiunhas.com (md)',
                        data: [],
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.08)',
                        borderWidth: 2, fill: true, tension: 0.4,
                        pointRadius: 2, pointHoverRadius: 5,
                        pointHoverBackgroundColor: '#a855f7'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { position: 'top' },
                    tooltip: tooltipStyle
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(30, 41, 59, 0.3)' },
                        ticks: { maxTicksLimit: 12 }
                    },
                    y: {
                        grid: { color: 'rgba(30, 41, 59, 0.3)' },
                        beginAtZero: true,
                        title: { display: true, text: 'Waktu Respons (md)', font: { size: 10 } }
                    }
                }
            }
        });
    }

    function createAttackTypes() {
        const ctx = document.getElementById('attackTypes');
        if (!ctx) return;

        chartInstances.attackTypes = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Ada', 'Tidak Ada'],
                datasets: [{
                    data: [0, 10],
                    backgroundColor: ['#00ff88', '#ff3b5c'],
                    borderColor: '#111927',
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { font: { size: 10 }, padding: 10 }
                    },
                    tooltip: tooltipStyle
                }
            }
        });
    }

    function createProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;

        chartInstances.protocolChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['himatika', 'fotografi'],
                datasets: [
                    {
                        label: 'Skor Keamanan (%)',
                        data: [0, 0],
                        backgroundColor: 'rgba(0, 212, 255, 0.7)',
                        borderRadius: 4
                    },
                    {
                        label: 'Header Tidak Ada',
                        data: [0, 0],
                        backgroundColor: 'rgba(255, 59, 92, 0.7)',
                        borderRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { font: { size: 10 } } },
                    tooltip: tooltipStyle
                },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(30, 41, 59, 0.3)' }, beginAtZero: true, max: 100 }
                }
            }
        });
    }

    function createSeverityTrend() {
        const ctx = document.getElementById('severityTrend');
        if (!ctx) return;

        chartInstances.severityTrend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Skor himatika',
                        data: [],
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.05)',
                        borderWidth: 2, fill: true, tension: 0.4, pointRadius: 3
                    },
                    {
                        label: 'Skor fotografi',
                        data: [],
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.05)',
                        borderWidth: 2, fill: true, tension: 0.4, pointRadius: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { font: { size: 9 }, padding: 10 } },
                    tooltip: tooltipStyle
                },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(30, 41, 59, 0.3)' }, beginAtZero: true, max: 100,
                         title: { display: true, text: 'Skor Keamanan %', font: { size: 9 } } }
                }
            }
        });
    }

    function createWAFChart() {
        const ctx = document.getElementById('wafChart');
        if (!ctx) return;

        chartInstances.wafChart = new Chart(ctx, {
            type: 'polarArea',
            data: {
                labels: ['Kritis', 'Tinggi', 'Sedang', 'Peringatan', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(255, 59, 92, 0.6)',
                        'rgba(249, 115, 22, 0.6)',
                        'rgba(245, 158, 11, 0.6)',
                        'rgba(168, 85, 247, 0.6)',
                        'rgba(0, 212, 255, 0.6)'
                    ],
                    borderColor: '#111927',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { font: { size: 9 }, padding: 8 } },
                    tooltip: tooltipStyle
                },
                scales: {
                    r: { grid: { color: 'rgba(30, 41, 59, 0.3)' }, ticks: { display: false } }
                }
            }
        });
    }

    function createBandwidthChart() {
        const ctx = document.getElementById('bandwidthChart');
        if (!ctx) return;

        const labels = Array.from({ length: 30 }, (_, i) => `${30 - i}s`);

        chartInstances.bandwidthChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        label: 'himatika (md)',
                        data: new Array(30).fill(null),
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        borderWidth: 2, fill: true, tension: 0.3, pointRadius: 0
                    },
                    {
                        label: 'fotografi (md)',
                        data: new Array(30).fill(null),
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.1)',
                        borderWidth: 2, fill: true, tension: 0.3, pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 0 },
                plugins: { legend: { position: 'top' }, tooltip: tooltipStyle },
                scales: {
                    x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } },
                    y: { grid: { color: 'rgba(30, 41, 59, 0.3)' }, beginAtZero: true,
                         title: { display: true, text: 'md', font: { size: 9 } } }
                }
            }
        });
    }

    function createConnectionChart() {
        const ctx = document.getElementById('connectionChart');
        if (!ctx) return;

        chartInstances.connectionChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Kode Status', 'Respons', 'SSL', 'Header', 'DNS', 'Waktu Aktif', 'Konten'],
                datasets: [
                    {
                        label: 'himatika',
                        data: [0, 0, 0, 0, 0, 0, 0],
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        borderWidth: 2, pointRadius: 3,
                        pointBackgroundColor: '#00d4ff'
                    },
                    {
                        label: 'fotografi',
                        data: [0, 0, 0, 0, 0, 0, 0],
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.1)',
                        borderWidth: 2, pointRadius: 3,
                        pointBackgroundColor: '#a855f7'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'top' } },
                scales: {
                    r: {
                        grid: { color: 'rgba(30, 41, 59, 0.3)' },
                        angleLines: { color: 'rgba(30, 41, 59, 0.3)' },
                        ticks: { display: false },
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    function updateFromScan(scanData) {
        if (!scanData) return;

        const timeline = chartInstances.threatTimeline;
        if (timeline) {
            const time = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            timeline.data.labels.push(time);
            timeline.data.datasets[0].data.push(scanData.himatika ? scanData.himatika.response_time_ms : 0);
            timeline.data.datasets[1].data.push(scanData.fotografi ? scanData.fotografi.response_time_ms : 0);
            if (timeline.data.labels.length > 50) {
                timeline.data.labels.shift();
                timeline.data.datasets.forEach(ds => ds.data.shift());
            }
            timeline.update('none');
        }

        const doughnut = chartInstances.attackTypes;
        if (doughnut) {
            let present = 0, missing = 0;
            for (const key of ['himatika', 'fotografi']) {
                if (scanData[key] && scanData[key].security_headers) {
                    for (const hdr of Object.values(scanData[key].security_headers)) {
                        if (hdr.present) present++; else missing++;
                    }
                }
            }
            doughnut.data.datasets[0].data = [present, missing];
            doughnut.update('none');
        }

        const bar = chartInstances.protocolChart;
        if (bar) {
            const himScore = scanData.himatika ? scanData.himatika.security_score : 0;
            const fotoScore = scanData.fotografi ? scanData.fotografi.security_score : 0;
            bar.data.datasets[0].data = [himScore, fotoScore];
            bar.data.datasets[1].data = [100 - himScore, 100 - fotoScore];
            bar.update('none');
        }

        const trend = chartInstances.severityTrend;
        if (trend) {
            const time = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
            trend.data.labels.push(time);
            trend.data.datasets[0].data.push(scanData.himatika ? scanData.himatika.security_score : 0);
            trend.data.datasets[1].data.push(scanData.fotografi ? scanData.fotografi.security_score : 0);
            if (trend.data.labels.length > 30) {
                trend.data.labels.shift();
                trend.data.datasets.forEach(ds => ds.data.shift());
            }
            trend.update('none');
        }

        const bw = chartInstances.bandwidthChart;
        if (bw) {
            bw.data.datasets[0].data.shift();
            bw.data.datasets[0].data.push(scanData.himatika ? scanData.himatika.response_time_ms : null);
            bw.data.datasets[1].data.shift();
            bw.data.datasets[1].data.push(scanData.fotografi ? scanData.fotografi.response_time_ms : null);
            bw.update('none');
        }

        const radar = chartInstances.connectionChart;
        if (radar) {
            for (let i = 0; i < 2; i++) {
                const key = i === 0 ? 'himatika' : 'fotografi';
                const site = scanData[key];
                if (!site) continue;

                const statusScore = site.status_code === 200 ? 100 : site.status_code < 400 ? 70 : site.status_code < 500 ? 30 : 0;
                const responseScore = Math.max(0, 100 - (site.response_time_ms / 50));
                const sslScore = site.ssl && site.ssl.valid ? 100 : 0;
                const headerScore = site.security_score || 0;
                const dnsScore = site.dns && site.dns.resolved ? 100 : 0;
                const uptimeScore = site.uptime_percent || 0;
                const contentScore = site.content_changed ? 50 : 100;

                radar.data.datasets[i].data = [
                    statusScore, Math.max(0, Math.min(100, responseScore)),
                    sslScore, headerScore, dnsScore, uptimeScore, contentScore
                ];
            }
            radar.update('none');
        }
    }

    function updateFromDashboard(dashData) {
        if (!dashData || !dashData.severity_counts) return;

        const polar = chartInstances.wafChart;
        if (polar) {
            const sc = dashData.severity_counts;
            polar.data.datasets[0].data = [
                sc.critical || 0, sc.high || 0, sc.medium || 0,
                sc.warning || 0, sc.info || 0
            ];
            polar.update('none');
        }
    }

    function initAll() {
        createThreatTimeline();
        createAttackTypes();
        createProtocolChart();
        createSeverityTrend();
        createWAFChart();
        createBandwidthChart();
        createConnectionChart();
    }

    function setFilter(filter) {
        const himHidden = (filter === 'fotografi');
        const fotoHidden = (filter === 'himatika');

        const timeline = chartInstances.threatTimeline;
        if (timeline) {
            timeline.data.datasets[0].hidden = himHidden;
            timeline.data.datasets[1].hidden = fotoHidden;
            timeline.update('none');
        }

        const trend = chartInstances.severityTrend;
        if (trend) {
            trend.data.datasets[0].hidden = himHidden;
            trend.data.datasets[1].hidden = fotoHidden;
            trend.update('none');
        }

        const bw = chartInstances.bandwidthChart;
        if (bw) {
            bw.data.datasets[0].hidden = himHidden;
            bw.data.datasets[1].hidden = fotoHidden;
            bw.update('none');
        }

        const radar = chartInstances.connectionChart;
        if (radar) {
            radar.data.datasets[0].hidden = himHidden;
            radar.data.datasets[1].hidden = fotoHidden;
            radar.update('none');
        }

        const bar = chartInstances.protocolChart;
        if (bar) {
            if (filter === 'all') {
                bar.data.labels = ['himatika', 'fotografi'];
            } else {
                bar.data.labels = [filter];
            }
            bar.update('none');
        }
    }

    return {
        initAll,
        chartInstances,
        updateFromScan,
        updateFromDashboard,
        setFilter
    };
})();
