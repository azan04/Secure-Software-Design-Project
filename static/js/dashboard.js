// Dashboard JavaScript for AnonyKit
let uploadedFile = null;
let uploadedData = null;
let columnConfig = {};
let riskChart = null;
let utilityChart = null;

// Initialize on page load
$(document).ready(function() {
    initializeEventHandlers();
    initializeCharts();
});

function initializeEventHandlers() {
    // File upload
    $('#fileInput').on('change', handleFileSelect);
    $('#uploadBtn').on('click', handleFileUpload);
    
    // Configuration
    $('#anonymizeBtn').on('click', handleAnonymize);
    
    // Download buttons
    $('#downloadBtn').on('click', downloadFile);
    $('#downloadReportBtn').on('click', downloadReport);
    
    // Toggle sections
    $('.k-anonymity-toggle input').on('change', function() {
        $('#kAnonymitySection').toggle(this.checked);
    });
    
    $('.l-diversity-toggle input').on('change', function() {
        $('#lDiversitySection').toggle(this.checked);
    });
    
    $('.dp-toggle input').on('change', function() {
        $('#dpSection').toggle(this.checked);
    });
}

function handleFileSelect(e) {
    uploadedFile = e.target.files[0];
    
    if (uploadedFile) {
        $('#uploadStatus').html(`
            <div class="alert alert-info">
                <i class="fas fa-file-csv"></i> <strong>Selected:</strong> ${uploadedFile.name} 
                (${AnonyKit.formatFileSize(uploadedFile.size)})
            </div>
        `);
        $('#uploadBtn').prop('disabled', false);
    } else {
        $('#uploadStatus').html(`
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i> Please select a CSV file
            </div>
        `);
        $('#uploadBtn').prop('disabled', true);
    }
}

function handleFileUpload() {
    if (!AnonyKit.validateFile(uploadedFile)) {
        return;
    }
    
    const formData = new FormData();
    formData.append('file', uploadedFile);
    
    AnonyKit.showLoading('Uploading file...');
    
    $.ajax({
        url: '/api/upload',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            AnonyKit.hideLoading();
            uploadedData = response;
            
            // Update status
            $('#uploadStatus').html(`
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> File uploaded successfully! 
                    <strong>${response.records} records</strong> loaded.
                </div>
            `);
            
            // Show preview
            displayPreview(response.preview);
            $('#dataPreview').show();
            
            // Initialize column configuration
            initializeColumnConfig(response.columns);
            
            // Populate dropdowns for advanced options
            populateAdvancedOptions(response.columns);
            
            // Show configuration section
            $('#configSection').show();
            
            AnonyKit.showAlert('File uploaded successfully!', 'success');
        },
        error: function() {
            AnonyKit.hideLoading();
        }
    });
}

function displayPreview(preview) {
    if (!preview || preview.length === 0) {
        $('#previewTable').html('<p class="text-muted">No preview available</p>');
        return;
    }
    
    const table = $('<table class="table table-sm table-bordered"></table>');
    const thead = $('<thead></thead>');
    const tbody = $('<tbody></tbody>');
    
    // Headers
    const headers = Object.keys(preview[0]);
    const headerRow = $('<tr></tr>');
    headers.forEach(h => headerRow.append(`<th>${h}</th>`));
    thead.append(headerRow);
    
    // Rows (limit to first 5)
    preview.slice(0, 5).forEach(row => {
        const tr = $('<tr></tr>');
        headers.forEach(h => {
            tr.append(`<td>${row[h] !== null && row[h] !== undefined ? row[h] : ''}</td>`);
        });
        tbody.append(tr);
    });
    
    table.append(thead, tbody);
    $('#previewTable').html(table);
    
    if (preview.length > 5) {
        $('#previewTable').append(`<p class="text-muted mt-2">Showing 5 of ${preview.length} rows</p>`);
    }
}

function initializeColumnConfig(columns) {
    const container = $('#columnConfig');
    container.empty();
    columnConfig = {};
    
    const row = $('<div class="row"></div>');
    columns.forEach(column => {
        const configCard = createColumnConfigCard(column);
        row.append(configCard);
        columnConfig[column] = { enabled: false, transform: 'mask' };
    });
    container.append(row);
}

function populateAdvancedOptions(columns) {
    // Populate quasi-identifiers dropdown
    const quasiSelect = $('#quasiIdentifiers');
    quasiSelect.empty();
    columns.forEach(col => {
        quasiSelect.append(`<option value="${col}">${col}</option>`);
    });
    
    // Populate sensitive attribute dropdown
    const sensitiveSelect = $('#sensitiveAttribute');
    sensitiveSelect.empty();
    sensitiveSelect.append('<option value="">Select...</option>');
    columns.forEach(col => {
        sensitiveSelect.append(`<option value="${col}">${col}</option>`);
    });
    
    // Populate DP columns dropdown
    const dpSelect = $('#dpColumns');
    dpSelect.empty();
    columns.forEach(col => {
        dpSelect.append(`<option value="${col}">${col}</option>`);
    });
    
    // Setup toggle handlers
    $('#enableKAnonymity').on('change', function() {
        $('#kAnonymityConfig').toggle(this.checked);
    });
    
    $('#enableLDiversity').on('change', function() {
        $('#lDiversityConfig').toggle(this.checked);
    });
    
    $('#enableDiffPrivacy').on('change', function() {
        $('#diffPrivacyConfig').toggle(this.checked);
    });
}

function createColumnConfigCard(column) {
    return `
        <div class="col-md-6 mb-3">
            <div class="card">
                <div class="card-body">
                    <div class="form-check form-switch mb-2">
                        <input class="form-check-input column-toggle" type="checkbox" 
                               id="toggle_${column}" data-column="${column}">
                        <label class="form-check-label fw-bold" for="toggle_${column}">
                            ${column}
                        </label>
                    </div>
                    <div class="column-config" id="config_${column}" style="display:none;">
                        <select class="form-select form-select-sm mb-2 transform-select" 
                                data-column="${column}">
                            <option value="mask">Character Masking</option>
                            <option value="substitute">Substitution</option>
                            <option value="shuffle">Shuffling</option>
                            <option value="null">Nulling</option>
                            <option value="generalize_age">Generalize Age</option>
                            <option value="generalize_numeric">Generalize Numeric</option>
                            <option value="hash">Salted Hash</option>
                            <option value="hmac">HMAC Pseudonymization</option>
                        </select>
                        <div class="mask-options" style="display:none;">
                            <input type="text" class="form-control form-control-sm" 
                                   placeholder="Mask character (default: *)" 
                                   data-column="${column}" data-param="mask_char">
                        </div>
                        <div class="generalize-options" style="display:none;">
                            <input type="number" class="form-control form-control-sm" 
                                   placeholder="Bin size" 
                                   data-column="${column}" data-param="bin_size">
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Event delegation for dynamically created elements
$(document).on('change', '.column-toggle', function() {
    const column = $(this).data('column');
    const isEnabled = $(this).is(':checked');
    
    columnConfig[column].enabled = isEnabled;
    $(`#config_${column}`).toggle(isEnabled);
});

$(document).on('change', '.transform-select', function() {
    const column = $(this).data('column');
    const transform = $(this).val();
    
    columnConfig[column].transform = transform;
    
    // Show/hide relevant options
    const card = $(this).closest('.card-body');
    card.find('.mask-options, .generalize-options').hide();
    
    if (transform === 'mask') {
        card.find('.mask-options').show();
    } else if (transform === 'generalize_age' || transform === 'generalize_numeric') {
        card.find('.generalize-options').show();
    }
});

$(document).on('input', '[data-param]', function() {
    const column = $(this).data('column');
    const param = $(this).data('param');
    const value = $(this).val();
    
    if (!columnConfig[column].params) {
        columnConfig[column].params = {};
    }
    columnConfig[column].params[param] = value;
});

function addColumnConfig() {
    const column = prompt('Enter column name:');
    if (column && !columnConfig[column]) {
        const configCard = createColumnConfigCard(column);
        $('#columnConfigContainer').append(configCard);
        columnConfig[column] = { enabled: false, transform: 'mask' };
    }
}

function handleAnonymize() {
    // Build configuration
    const config = {
        filename: uploadedData.filename,
        profile: {
            columns: {},
            hmac_key: $('#hmacKey').val() || ''
        }
    };
    
    // Column transforms
    Object.keys(columnConfig).forEach(column => {
        if (columnConfig[column].enabled) {
            config.profile.columns[column] = {
                transform: columnConfig[column].transform,
                params: columnConfig[column].params || {}
            };
        }
    });
    
    // K-Anonymity
    if ($('#enableKAnonymity').is(':checked')) {
        config.profile.apply_k_anonymity = true;
        config.profile.k = parseInt($('#kValue').val()) || 2;
        config.profile.quasi_identifiers = $('#quasiIdentifiers').val() || [];
    }
    
    // L-Diversity
    if ($('#enableLDiversity').is(':checked')) {
        config.profile.l = parseInt($('#lValue').val()) || 2;
        config.profile.sensitive_attribute = $('#sensitiveAttribute').val() || null;
    }
    
    // Differential Privacy
    if ($('#enableDiffPrivacy').is(':checked')) {
        config.profile.apply_differential_privacy = true;
        config.profile.epsilon = parseFloat($('#epsilon').val()) || 1.0;
        config.profile.dp_columns = $('#dpColumns').val() || [];
    }
    
    // Validate configuration
    const hasTransforms = Object.keys(config.profile.columns).length > 0;
    const hasKAnon = config.profile.apply_k_anonymity === true;
    const hasLDiv = config.profile.l && config.profile.l > 0;
    const hasDP = config.profile.apply_differential_privacy === true;
    
    if (!hasTransforms && !hasKAnon && !hasLDiv && !hasDP) {
        AnonyKit.showAlert('Please configure at least one anonymization method', 'warning');
        return;
    }
    
    AnonyKit.showLoading('Anonymizing data...');
    
    $.ajax({
        url: '/api/anonymize',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(config),
        success: function(response) {
            AnonyKit.hideLoading();
            displayResults(response);
            
            // Show results section
            $('#resultsSection').show();
            
            // Scroll to results
            $('html, body').animate({
                scrollTop: $('#resultsSection').offset().top - 100
            }, 500);
            
            AnonyKit.showAlert('Data anonymized successfully!', 'success');
        },
        error: function(xhr) {
            AnonyKit.hideLoading();
            const errorMsg = xhr.responseJSON?.error || 'Anonymization failed';
            AnonyKit.showAlert(errorMsg, 'danger');
        }
    });
}

function displayResults(results) {
    // Store output filename
    window.outputFilename = results.output_filename;
    window.reportData = results.report;
    
    // Update metrics cards
    $('#originalRecords').text(AnonyKit.formatNumber(results.original_records));
    $('#anonymizedRecords').text(AnonyKit.formatNumber(results.anonymized_records));
    $('#suppressedRecords').text(AnonyKit.formatNumber(results.suppressed_records));
    
    // Calculate retention rate
    const retentionRate = results.original_records > 0 
        ? (results.anonymized_records / results.original_records * 100).toFixed(1) 
        : 0;
    $('#privacyStatus').text(retentionRate + '%');
    
    // Update charts if report data exists
    if (results.report) {
        const privacyMetrics = results.report.privacy_metrics || {};
        const utilityMetrics = results.report.utility_metrics || {};
        
        // Calculate risk score from k-anonymity/l-diversity
        const riskScore = privacyMetrics.k_anonymity?.satisfies_k_anonymity ? 20 : 80;
        updateRiskChart({ risk_score: riskScore / 100 });
        
        // Update utility chart
        const dataRetention = utilityMetrics.data_retention_rate || retentionRate;
        const infoLoss = utilityMetrics.information_loss || (100 - retentionRate);
        updateUtilityChart({ retention_rate: dataRetention / 100, information_loss: infoLoss / 100 });
    }
    
    // Display preview of anonymized data
    if (results.preview && results.preview.length > 0) {
        const table = $('#resultsTable');
        const thead = table.find('thead');
        const tbody = table.find('tbody');
        
        thead.empty();
        tbody.empty();
        
        const headers = Object.keys(results.preview[0]);
        const headerRow = $('<tr></tr>');
        headers.forEach(h => headerRow.append(`<th>${h}</th>`));
        thead.append(headerRow);
        
        results.preview.forEach(row => {
            const tr = $('<tr></tr>');
            headers.forEach(h => {
                const val = row[h] !== null && row[h] !== undefined ? row[h] : '';
                tr.append(`<td>${val}</td>`);
            });
            tbody.append(tr);
        });
    }
    
    // Enable download buttons
    $('#downloadBtn, #downloadReportBtn').prop('disabled', false);
}

function initializeCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            }
        }
    };
    
    // Risk Chart
    const riskCtx = document.getElementById('riskChart');
    if (riskCtx) {
        riskChart = new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Risk Score', 'Safety Margin'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#dc3545', '#28a745'],
                    borderWidth: 0
                }]
            },
            options: {
                ...chartOptions,
                cutout: '70%'
            }
        });
    }
    
    // Utility Chart
    const utilityCtx = document.getElementById('utilityChart');
    if (utilityCtx) {
        utilityChart = new Chart(utilityCtx, {
            type: 'bar',
            data: {
                labels: ['Data Retention', 'Information Loss'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#007bff', '#ffc107'],
                    borderWidth: 0
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }
}

function updateRiskChart(metrics) {
    if (!riskChart) return;
    
    const riskScore = (metrics.risk_score || 0) * 100;
    const safetyMargin = 100 - riskScore;
    
    riskChart.data.datasets[0].data = [riskScore, safetyMargin];
    riskChart.update();
}

function updateUtilityChart(metrics) {
    if (!utilityChart) return;
    
    const retention = (metrics.retention_rate || 0) * 100;
    const informationLoss = (metrics.information_loss || 0) * 100;
    
    utilityChart.data.datasets[0].data = [retention, informationLoss];
    utilityChart.update();
}

function downloadFile(format) {
    if (!window.outputFilename) {
        AnonyKit.showAlert('No file available for download', 'warning');
        return;
    }
    
    const url = `/api/download/${window.outputFilename}`;
    window.location.href = url;
}

function downloadReport() {
    if (!window.reportData) {
        AnonyKit.showAlert('No report data available', 'warning');
        return;
    }
    
    AnonyKit.downloadJSON(window.reportData, 'anonymization_report.json');
}
