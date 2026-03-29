// ── Tab Switching ─────────────────────────────────
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

    if (tab === 'manual') {
        document.getElementById('tab-manual').style.display = 'block';
        document.getElementById('tab-csv').style.display = 'none';
        document.querySelectorAll('.tab-btn')[0].classList.add('active');
    } else {
        document.getElementById('tab-manual').style.display = 'none';
        document.getElementById('tab-csv').style.display = 'block';
        document.querySelectorAll('.tab-btn')[1].classList.add('active');
    }
}

// ── Model Selector ────────────────────────────────
document.querySelectorAll('.model-option').forEach(label => {
    label.addEventListener('click', () => {
        document.querySelectorAll('.model-option').forEach(l => l.classList.remove('active'));
        label.classList.add('active');
    });
});

// ── CSV File Selection ────────────────────────────
document.getElementById('csv-file').addEventListener('change', function () {
    const fileName = this.files[0] ? this.files[0].name : 'No file selected';
    document.getElementById('file-name').textContent = fileName;
});

// Drag and drop
const uploadArea = document.getElementById('csv-upload-area');

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.style.borderColor = '#00d4ff';
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.style.borderColor = '#2a3050';
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.style.borderColor = '#2a3050';
    const file = e.dataTransfer.files[0];
    if (file) {
        document.getElementById('csv-file').files = e.dataTransfer.files;
        document.getElementById('file-name').textContent = file.name;
    }
});

// ── Collect Form Data ─────────────────────────────
function getFormData() {
    return {
        model: document.querySelector('input[name="model"]:checked').value,
        protocol_type: document.getElementById('protocol_type').value,
        service: document.getElementById('service').value,
        flag: document.getElementById('flag').value,
        duration: document.getElementById('duration').value,
        src_bytes: document.getElementById('src_bytes').value,
        dst_bytes: document.getElementById('dst_bytes').value,
        count: document.getElementById('count').value,
        srv_count: document.getElementById('srv_count').value,
        serror_rate: document.getElementById('serror_rate').value,
        rerror_rate: document.getElementById('rerror_rate').value,
        same_srv_rate: document.getElementById('same_srv_rate').value,
        diff_srv_rate: document.getElementById('diff_srv_rate').value,
        dst_host_count: document.getElementById('dst_host_count').value,
        dst_host_srv_count: document.getElementById('dst_host_srv_count').value,
        dst_host_same_srv_rate: document.getElementById('dst_host_same_srv_rate').value,
        dst_host_diff_srv_rate: document.getElementById('dst_host_diff_srv_rate').value,
        dst_host_serror_rate: document.getElementById('dst_host_serror_rate').value,
        dst_host_rerror_rate: document.getElementById('dst_host_rerror_rate').value,
    };
}

// ── Manual Predict ────────────────────────────────
async function predict() {
    const btn = document.querySelector('.predict-btn');
    btn.textContent = '⏳ Analyzing...';
    btn.disabled = true;

    const data = getFormData();

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (result.status === 'success') {
            showResult(result);
        } else {
            alert('Error: ' + result.message);
        }

    } catch (error) {
        alert('Connection error: ' + error.message);
    } finally {
        btn.textContent = '🔍 Detect Intrusion';
        btn.disabled = false;
    }
}

// ── Show Manual Result ────────────────────────────
function showResult(result) {
    const card = document.getElementById('result-card');
    const box = document.getElementById('result-box');
    const icon = document.getElementById('result-icon');
    const label = document.getElementById('result-label');
    const model = document.getElementById('result-model');

    box.className = 'result-box';

    const prediction = result.prediction;

    if (prediction === 'Normal') {
        icon.textContent = '✅';
        label.textContent = 'NORMAL TRAFFIC';
        box.classList.add('result-normal');
    } else if (prediction === 'DoS') {
        icon.textContent = '🚨';
        label.textContent = 'DoS ATTACK DETECTED';
        box.classList.add('result-attack');
    } else if (prediction === 'Probe') {
        icon.textContent = '⚠️';
        label.textContent = 'PROBE ATTACK DETECTED';
        box.classList.add('result-warning');
    } else if (prediction === 'R2L') {
        icon.textContent = '🚨';
        label.textContent = 'R2L ATTACK DETECTED';
        box.classList.add('result-attack');
    } else if (prediction === 'U2R') {
        icon.textContent = '🚨';
        label.textContent = 'U2R ATTACK DETECTED';
        box.classList.add('result-attack');
    }

    model.textContent = `Detected using: ${result.model_used}`;

    card.style.display = 'block';
    card.scrollIntoView({ behavior: 'smooth' });
}

// ── CSV Predict ───────────────────────────────────
async function predictCSV() {
    const fileInput = document.getElementById('csv-file');

    if (!fileInput.files[0]) {
        alert('Please select a CSV file first!');
        return;
    }

    const btn = document.querySelectorAll('.predict-btn')[1];
    btn.textContent = '⏳ Analysing...';
    btn.disabled = true;

    const model = document.querySelector('input[name="model"]:checked').value;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        const response = await fetch(`/predict_csv?model=${model}`, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.status === 'success') {
            showCSVResults(result);
        } else {
            alert('Error: ' + result.message);
        }

    } catch (error) {
        alert('Connection error: ' + error.message);
    } finally {
        btn.textContent = '🔍 Analyse CSV';
        btn.disabled = false;
    }
}

// ── Show CSV Results ──────────────────────────────
function showCSVResults(result) {
    const card = document.getElementById('csv-result-card');

    // Summary
    const summaryGrid = document.getElementById('summary-grid');
    summaryGrid.innerHTML = '';

    const icons = {
        'Normal': '✅', 'DoS': '🚨',
        'Probe': '⚠️', 'R2L': '🚨', 'U2R': '🚨'
    };
    const colorClass = {
        'Normal': 'summary-normal', 'DoS': 'summary-attack',
        'Probe': 'summary-warning', 'R2L': 'summary-attack',
        'U2R': 'summary-attack'
    };

    // Total card
    summaryGrid.innerHTML += `
        <div class="summary-card summary-total">
            <div class="summary-icon">📊</div>
            <div class="summary-count">${result.total}</div>
            <div class="summary-label">Total Connections</div>
        </div>`;

    // Per category cards
    for (const [pred, count] of Object.entries(result.summary)) {
        summaryGrid.innerHTML += `
            <div class="summary-card ${colorClass[pred] || ''}">
                <div class="summary-icon">${icons[pred] || '❓'}</div>
                <div class="summary-count">${count}</div>
                <div class="summary-label">${pred}</div>
            </div>`;
    }

    // Results table
    const tbody = document.getElementById('results-tbody');
    tbody.innerHTML = '';

    result.results.forEach(r => {
        const icon = icons[r.prediction] || '❓';
        const cls = r.prediction === 'Normal' ? 'row-normal' :
            r.prediction === 'Probe' ? 'row-warning' : 'row-attack';

        tbody.innerHTML += `
            <tr class="${cls}">
                <td>#${r.connection}</td>
                <td>${icon} ${r.prediction}</td>
                <td>${r.prediction === 'Normal' ? '✅ Safe' : '🚨 Threat!'}</td>
            </tr>`;
    });

    card.style.display = 'block';
    card.scrollIntoView({ behavior: 'smooth' });
}
