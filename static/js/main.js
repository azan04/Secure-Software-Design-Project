// Main JavaScript for AnonyKit

// Show loading overlay
function showLoading(message = 'Processing...') {
    const overlay = $('<div class="loading-overlay"><div class="text-center text-white"><div class="spinner-border mb-3"></div><h4>' + message + '</h4></div></div>');
    $('body').append(overlay);
}

// Hide loading overlay
function hideLoading() {
    $('.loading-overlay').remove();
}

// Show alert message
function showAlert(message, type = 'info') {
    const alert = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    $('.container-fluid').prepend(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        $('.alert').fadeOut(() => $(this).remove());
    }, 5000);
}

// Format numbers with commas
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Format percentage
function formatPercent(num) {
    return (num * 100).toFixed(2) + '%';
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Create table from data
function createTable(data, tableId) {
    if (!data || data.length === 0) return;
    
    const table = $(`#${tableId}`);
    const thead = table.find('thead');
    const tbody = table.find('tbody');
    
    // Clear existing content
    thead.empty();
    tbody.empty();
    
    // Create header
    const headers = Object.keys(data[0]);
    const headerRow = $('<tr></tr>');
    headers.forEach(header => {
        headerRow.append(`<th>${header}</th>`);
    });
    thead.append(headerRow);
    
    // Create rows
    data.forEach(row => {
        const tr = $('<tr></tr>');
        headers.forEach(header => {
            tr.append(`<td>${row[header] !== null && row[header] !== undefined ? row[header] : ''}</td>`);
        });
        tbody.append(tr);
    });
}

// Download JSON as file
function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Validate file
function validateFile(file) {
    if (!file) {
        showAlert('Please select a file', 'danger');
        return false;
    }
    
    if (!file.name.endsWith('.csv')) {
        showAlert('Only CSV files are allowed', 'danger');
        return false;
    }
    
    if (file.size > 50 * 1024 * 1024) {
        showAlert('File size must be less than 50MB', 'danger');
        return false;
    }
    
    return true;
}

// Initialize tooltips
$(document).ready(function() {
    $('[data-bs-toggle="tooltip"]').tooltip();
});

// Handle AJAX errors
$(document).ajaxError(function(event, jqxhr, settings, thrownError) {
    hideLoading();
    
    let errorMessage = 'An error occurred';
    
    if (jqxhr.responseJSON && jqxhr.responseJSON.error) {
        errorMessage = jqxhr.responseJSON.error;
    } else if (jqxhr.statusText) {
        errorMessage = jqxhr.statusText;
    }
    
    showAlert(errorMessage, 'danger');
});

// Export functions for use in other scripts
window.AnonyKit = {
    showLoading,
    hideLoading,
    showAlert,
    formatNumber,
    formatPercent,
    formatFileSize,
    createTable,
    downloadJSON,
    validateFile
};
