document.querySelectorAll('.model-option').forEach(label => {
    label.addEventListener('click', () => {
        document.querySelectorAll('.model-option').forEach(l => l.classList.remove('active'));
        label.classList.add('active');
    });
});

// ── Collect Form Data ─────────────────────────────
function getFormData() {
    return {
        // Model choice
        model: document.querySelector('input[name="model"]:checked').value,

        // Categorical
        protocol_type: document.getElementById('protocol_type').value,
        service: document.getElementById('service').value,
        flag: document.getElementById('flag').value,

        // Basic numerical
        duration: document.getElementById('duration').value,
        src_bytes: document.getElementById('src_bytes').value,
        dst_bytes: document.getElementById('dst_bytes').value,

        // Traffic features
        count: document.getElementById('count').value,
        srv_count: document.getElementById('srv_count').value,
        serror_rate: document.getElementById('serror_rate').value,
        rerror_rate: document.getElementById('rerror_rate').value,
        same_srv_rate: document.getElementById('same_srv_rate').value,
        diff_srv_rate: document.getElementById('diff_srv_rate').value,

        // Host features
        dst_host_count: document.getElementById('dst_host_count').value,
        dst_host_srv_count: document.getElementById('dst_host_srv_count').value,
        dst_host_same_srv_rate: document.getElementById('dst_host_same_srv_rate').value,
        dst_host_diff_srv_rate: document.getElementById('dst_host_diff_srv_rate').value,
        dst_host_serror_rate: document.getElementById('dst_host_serror_rate').value,
        dst_host_rerror_rate: document.getElementById('dst_host_rerror_rate').value,
    };
}

// ── Predict Function ──────────────────────────────
async function predict() {
    const btn = document.querySelector('.predict-btn');

    // Loading state
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

// ── Show Result ───────────────────────────────────
function showResult(result) {
    const card = document.getElementById('result-card');
    const box = document.getElementById('result-box');
    const icon = document.getElementById('result-icon');
    const label = document.getElementById('result-label');
    const model = document.getElementById('result-model');

    // Reset classes
    box.className = 'result-box';

    // Set content based on prediction
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

    // Show card with animation
    card.style.display = 'block';
    card.scrollIntoView({ behavior: 'smooth' });
}