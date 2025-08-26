// Dashboard-specific JavaScript functionality

let severityChart = null;
let trendsChart = null;

function initializeCharts() {
    initializeSeverityChart();
    initializeTrendsChart();
    
    // Update charts periodically
    setInterval(updateCharts, 30000); // Update every 30 seconds
}

function initializeSeverityChart() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    fetch('/api/vulnerability_stats')
        .then(response => response.json())
        .then(data => {
            const chartData = data.by_severity;
            
            severityChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [
                            chartData.critical || 0,
                            chartData.high || 0,
                            chartData.medium || 0,
                            chartData.low || 0
                        ],
                        backgroundColor: [
                            '#dc3545', // Critical - Red
                            '#fd7e14', // High - Orange
                            '#ffc107', // Medium - Yellow
                            '#198754'  // Low - Green
                        ],
                        borderWidth: 2,
                        borderColor: '#495057'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#adb5bd',
                                usePointStyle: true,
                                padding: 20
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0,0,0,0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: '#6c757d',
                            borderWidth: 1
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error loading severity chart:', error));
}

function initializeTrendsChart() {
    const ctx = document.getElementById('trendsChart');
    if (!ctx) return;
    
    fetch('/api/dashboard_data')
        .then(response => response.json())
        .then(data => {
            const metrics = data.metrics.reverse(); // Show oldest to newest
            
            trendsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: metrics.map(m => new Date(m.date).toLocaleDateString()),
                    datasets: [
                        {
                            label: 'Total Scans',
                            data: metrics.map(m => m.total_scans),
                            borderColor: '#0d6efd',
                            backgroundColor: 'rgba(13, 110, 253, 0.1)',
                            tension: 0.4,
                            fill: true
                        },
                        {
                            label: 'Vulnerabilities',
                            data: metrics.map(m => m.total_vulnerabilities),
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            tension: 0.4,
                            fill: true
                        },
                        {
                            label: 'Critical Vulns',
                            data: metrics.map(m => m.critical_vulnerabilities),
                            borderColor: '#fd7e14',
                            backgroundColor: 'rgba(253, 126, 20, 0.1)',
                            tension: 0.4,
                            fill: false
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: 'index'
                    },
                    plugins: {
                        legend: {
                            labels: {
                                color: '#adb5bd',
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0,0,0,0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: '#6c757d',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#6c757d'
                            },
                            grid: {
                                color: 'rgba(108, 117, 125, 0.2)'
                            }
                        },
                        y: {
                            ticks: {
                                color: '#6c757d'
                            },
                            grid: {
                                color: 'rgba(108, 117, 125, 0.2)'
                            }
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error loading trends chart:', error));
}

function updateCharts() {
    if (severityChart) {
        fetch('/api/vulnerability_stats')
            .then(response => response.json())
            .then(data => {
                const chartData = data.by_severity;
                severityChart.data.datasets[0].data = [
                    chartData.critical || 0,
                    chartData.high || 0,
                    chartData.medium || 0,
                    chartData.low || 0
                ];
                severityChart.update();
            })
            .catch(error => console.error('Error updating severity chart:', error));
    }
    
    if (trendsChart) {
        fetch('/api/dashboard_data')
            .then(response => response.json())
            .then(data => {
                const metrics = data.metrics.reverse();
                
                trendsChart.data.labels = metrics.map(m => new Date(m.date).toLocaleDateString());
                trendsChart.data.datasets[0].data = metrics.map(m => m.total_scans);
                trendsChart.data.datasets[1].data = metrics.map(m => m.total_vulnerabilities);
                trendsChart.data.datasets[2].data = metrics.map(m => m.critical_vulnerabilities);
                
                trendsChart.update();
            })
            .catch(error => console.error('Error updating trends chart:', error));
    }
}

function updateDashboardMetrics() {
    fetch('/api/dashboard_data')
        .then(response => response.json())
        .then(data => {
            // Update running scans count
            const runningScansElement = document.getElementById('running-scans-count');
            if (runningScansElement) {
                runningScansElement.textContent = data.running_scans.length;
            }
            
            // Update active scans in status bar
            const activeScansCount = document.getElementById('active-scans-count');
            if (activeScansCount) {
                activeScansCount.textContent = data.running_scans.length;
            }
            
            // Update recent alerts
            updateRecentAlerts(data.recent_vulnerabilities);
            
            // Update scan progress
            updateScanProgress(data.running_scans);
        })
        .catch(error => console.error('Error updating dashboard metrics:', error));
}

function updateRecentAlerts(vulnerabilities) {
    const alertsContainer = document.getElementById('recent-alerts');
    if (!alertsContainer) return;
    
    if (vulnerabilities.length === 0) {
        alertsContainer.innerHTML = `
            <div class="text-center py-3 text-muted">
                <i data-feather="shield-off" width="32" height="32" class="mb-2"></i>
                <p class="mb-0">No recent alerts</p>
            </div>
        `;
        feather.replace();
        return;
    }
    
    const alertsHtml = vulnerabilities.slice(0, 5).map(vuln => {
        const severityColor = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        }[vuln.severity] || 'secondary';
        
        return `
            <div class="alert alert-${severityColor} alert-sm mb-2">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <strong>${vuln.vulnerability_type}</strong>
                        <small class="d-block text-muted">${vuln.description.substring(0, 80)}...</small>
                    </div>
                    <span class="badge bg-${severityColor}">${vuln.severity}</span>
                </div>
            </div>
        `;
    }).join('');
    
    alertsContainer.innerHTML = alertsHtml;
}

function updateScanProgress(runningScans) {
    const container = document.getElementById('active-scans-container');
    if (!container) return;
    
    if (runningScans.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4 text-muted">
                <i data-feather="search" width="48" height="48" class="mb-3"></i>
                <p>No active scans running</p>
                <button class="btn btn-primary" onclick="startScan('SAST')">Start New Scan</button>
            </div>
        `;
        feather.replace();
        return;
    }
    
    const scansHtml = runningScans.map(scan => `
        <div class="scan-progress mb-3" data-scan-id="${scan.id}">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <div>
                    <strong>${scan.scan_type} Scan</strong>
                    <small class="text-muted ms-2">${scan.target}</small>
                </div>
                <span class="badge bg-primary">${scan.progress}%</span>
            </div>
            <div class="progress mb-2">
                <div class="progress-bar bg-primary" role="progressbar" 
                     style="width: ${scan.progress}%" 
                     aria-valuenow="${scan.progress}" 
                     aria-valuemin="0" 
                     aria-valuemax="100"></div>
            </div>
            <small class="text-muted">
                ${scan.scanned_files}/${scan.total_files} files scanned
                • ${scan.vulnerabilities_found} vulnerabilities found
            </small>
        </div>
    `).join('');
    
    container.innerHTML = scansHtml;
}

function startRealTimeUpdates() {
    // Update dashboard metrics every 5 seconds
    setInterval(updateDashboardMetrics, 5000);
    
    // Initial load
    updateDashboardMetrics();
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    startRealTimeUpdates();
});
