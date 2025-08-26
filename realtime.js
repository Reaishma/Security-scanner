// Real-time updates using Server-Sent Events and periodic polling

class RealtimeUpdater {
    constructor() {
        this.eventSource = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 5000; // 5 seconds
        
        this.init();
    }
    
    init() {
        this.connectEventSource();
        this.startPolling();
        this.setupConnectionStatusMonitoring();
    }
    
    connectEventSource() {
        try {
            this.eventSource = new EventSource('/api/events');
            
            this.eventSource.onopen = () => {
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.updateConnectionStatus('connected');
                console.log('Real-time connection established');
            };
            
            this.eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleRealtimeUpdate(data);
                } catch (error) {
                    console.error('Error parsing real-time data:', error);
                }
            };
            
            this.eventSource.onerror = () => {
                this.isConnected = false;
                this.updateConnectionStatus('disconnected');
                this.handleReconnection();
                console.error('Real-time connection error');
            };
            
        } catch (error) {
            console.error('Error establishing real-time connection:', error);
            this.fallbackToPolling();
        }
    }
    
    handleRealtimeUpdate(data) {
        switch (data.type) {
            case 'scan_progress':
                this.updateScanProgress(data.scan);
                break;
            case 'new_vulnerability':
                this.handleNewVulnerability(data.vulnerability);
                break;
            case 'scan_complete':
                this.handleScanComplete(data.scan);
                break;
            default:
                console.log('Unknown real-time update type:', data.type);
        }
    }
    
    updateScanProgress(scan) {
        // Update progress bars
        const progressElements = document.querySelectorAll(`[data-scan-id="${scan.id}"]`);
        progressElements.forEach(element => {
            const progressBar = element.querySelector('.progress-bar');
            const progressBadge = element.querySelector('.badge');
            const scanInfo = element.querySelector('small');
            
            if (progressBar) {
                progressBar.style.width = `${scan.progress}%`;
                progressBar.setAttribute('aria-valuenow', scan.progress);
            }
            
            if (progressBadge) {
                progressBadge.textContent = `${scan.progress}%`;
            }
            
            if (scanInfo) {
                scanInfo.textContent = `${scan.scanned_files}/${scan.total_files} files scanned • ${scan.vulnerabilities_found} vulnerabilities found`;
            }
        });
        
        // Update running scans count
        this.updateRunningScansCount();
    }
    
    handleNewVulnerability(vulnerability) {
        // Show notification
        this.showNotification('warning', `New ${vulnerability.severity} vulnerability found: ${vulnerability.vulnerability_type}`);
        
        // Update vulnerability counts
        this.updateVulnerabilityCount(vulnerability.severity);
        
        // Add to recent alerts if on dashboard
        this.addToRecentAlerts(vulnerability);
    }
    
    handleScanComplete(scan) {
        // Show completion notification
        this.showNotification('success', `${scan.scan_type} scan completed for ${scan.target}`);
        
        // Update UI elements
        this.removeScanProgress(scan.id);
        this.updateRunningScansCount();
        
        // Refresh charts if on dashboard
        if (typeof updateCharts === 'function') {
            updateCharts();
        }
    }
    
    updateRunningScansCount() {
        fetch('/api/dashboard_data')
            .then(response => response.json())
            .then(data => {
                const runningCount = data.running_scans.length;
                
                const elements = document.querySelectorAll('#running-scans-count, #active-scans-count');
                elements.forEach(element => {
                    if (element) element.textContent = runningCount;
                });
            })
            .catch(error => console.error('Error updating running scans count:', error));
    }
    
    updateVulnerabilityCount(severity) {
        const countElement = document.getElementById(`${severity}-vulns-count`);
        if (countElement) {
            const currentCount = parseInt(countElement.textContent) || 0;
            countElement.textContent = currentCount + 1;
        }
        
        const totalElement = document.getElementById('total-vulns-count');
        if (totalElement) {
            const currentCount = parseInt(totalElement.textContent) || 0;
            totalElement.textContent = currentCount + 1;
        }
    }
    
    addToRecentAlerts(vulnerability) {
        const alertsContainer = document.getElementById('recent-alerts');
        if (!alertsContainer) return;
        
        const severityColor = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        }[vulnerability.severity] || 'secondary';
        
        const alertHtml = `
            <div class="alert alert-${severityColor} alert-sm mb-2 new-alert">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <strong>${vulnerability.vulnerability_type}</strong>
                        <small class="d-block text-muted">${vulnerability.description.substring(0, 80)}...</small>
                    </div>
                    <span class="badge bg-${severityColor}">${vulnerability.severity}</span>
                </div>
            </div>
        `;
        
        alertsContainer.insertAdjacentHTML('afterbegin', alertHtml);
        
        // Remove oldest alert if more than 5
        const alerts = alertsContainer.querySelectorAll('.alert');
        if (alerts.length > 5) {
            alerts[alerts.length - 1].remove();
        }
        
        // Highlight new alert
        setTimeout(() => {
            const newAlert = alertsContainer.querySelector('.new-alert');
            if (newAlert) {
                newAlert.classList.remove('new-alert');
            }
        }, 3000);
    }
    
    removeScanProgress(scanId) {
        const scanElement = document.querySelector(`[data-scan-id="${scanId}"]`);
        if (scanElement) {
            scanElement.style.transition = 'opacity 0.5s';
            scanElement.style.opacity = '0';
            setTimeout(() => {
                scanElement.remove();
                
                // Check if no more active scans
                const container = document.getElementById('active-scans-container');
                if (container && container.children.length === 0) {
                    container.innerHTML = `
                        <div class="text-center py-4 text-muted">
                            <i data-feather="search" width="48" height="48" class="mb-3"></i>
                            <p>No active scans running</p>
                            <button class="btn btn-primary" onclick="startScan('SAST')">Start New Scan</button>
                        </div>
                    `;
                    feather.replace();
                }
            }, 500);
        }
    }
    
    showNotification(type, message) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 1050;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i data-feather="${type === 'success' ? 'check-circle' : type === 'warning' ? 'alert-triangle' : 'info'}" class="me-2"></i>
                <div class="flex-grow-1">${message}</div>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        document.body.appendChild(notification);
        feather.replace();
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
    
    handleReconnection() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
            
            setTimeout(() => {
                this.connectEventSource();
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            console.log('Max reconnection attempts reached. Falling back to polling.');
            this.fallbackToPolling();
        }
    }
    
    fallbackToPolling() {
        // Increase polling frequency when real-time connection fails
        this.pollingInterval = setInterval(() => {
            this.pollForUpdates();
        }, 3000); // Poll every 3 seconds
    }
    
    startPolling() {
        // Basic polling as backup (less frequent)
        this.pollingInterval = setInterval(() => {
            if (!this.isConnected) {
                this.pollForUpdates();
            }
        }, 10000); // Poll every 10 seconds when connected
    }
    
    pollForUpdates() {
        fetch('/api/dashboard_data')
            .then(response => response.json())
            .then(data => {
                // Update running scans
                data.running_scans.forEach(scan => {
                    this.updateScanProgress(scan);
                });
                
                // Update pending alerts count
                const pendingAlertsElement = document.getElementById('pending-alerts-count');
                if (pendingAlertsElement) {
                    pendingAlertsElement.textContent = data.recent_vulnerabilities.length;
                }
            })
            .catch(error => console.error('Polling error:', error));
    }
    
    setupConnectionStatusMonitoring() {
        // Monitor connection status
        setInterval(() => {
            if (this.eventSource) {
                if (this.eventSource.readyState === EventSource.CLOSED) {
                    this.isConnected = false;
                    this.updateConnectionStatus('disconnected');
                } else if (this.eventSource.readyState === EventSource.OPEN) {
                    this.isConnected = true;
                    this.updateConnectionStatus('connected');
                }
            }
        }, 5000);
    }
    
    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connection-status');
        if (!statusElement) return;
        
        if (status === 'connected') {
            statusElement.className = 'badge bg-success me-2';
            statusElement.innerHTML = '<i data-feather="wifi" width="12" height="12"></i> Connected';
        } else {
            statusElement.className = 'badge bg-danger me-2';
            statusElement.innerHTML = '<i data-feather="wifi-off" width="12" height="12"></i> Disconnected';
        }
        
        feather.replace();
    }
    
    destroy() {
        if (this.eventSource) {
            this.eventSource.close();
        }
        
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }
    }
}

// Initialize real-time updater when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    window.realtimeUpdater = new RealtimeUpdater();
});

// Clean up on page unload
window.addEventListener('beforeunload', function() {
    if (window.realtimeUpdater) {
        window.realtimeUpdater.destroy();
    }
});
