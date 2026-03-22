from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
import pandas as pd
import os

app = Flask(__name__)

# ── Load models and assets ──────────────────────────
BASE = os.path.join(os.path.dirname(__file__), 'models')

with open(f'{BASE}/rf_rfe.pkl',  'rb') as f: rf_model  = pickle.load(f)
with open(f'{BASE}/svm_rfe.pkl', 'rb') as f: svm_model = pickle.load(f)
with open(f'{BASE}/scaler.pkl',  'rb') as f: scaler    = pickle.load(f)

with open(f'{BASE}/rf_selected_features.pkl',  'rb') as f:
    rf_features  = pickle.load(f)
with open(f'{BASE}/svm_selected_features.pkl', 'rb') as f:
    svm_features = pickle.load(f)
with open(f'{BASE}/all_features.pkl', 'rb') as f:
    all_features = pickle.load(f)

print("✅ All models loaded successfully!")

# ── Helper: build full feature vector ───────────────
def prepare_input(form_data):
    # Start with all zeros
    input_dict = {col: 0 for col in all_features}

    # Fill in numerical values
    numerical_fields = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
        'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]

    for field in numerical_fields:
        if field in form_data:
            input_dict[field] = float(form_data[field])

    # One hot encode protocol_type
    protocol = form_data.get('protocol_type', 'tcp')
    if f'protocol_type_{protocol}' in input_dict:
        input_dict[f'protocol_type_{protocol}'] = 1

    # One hot encode service
    service = form_data.get('service', 'http')
    if f'service_{service}' in input_dict:
        input_dict[f'service_{service}'] = 1

    # One hot encode flag
    flag = form_data.get('flag', 'SF')
    if f'flag_{flag}' in input_dict:
        input_dict[f'flag_{flag}'] = 1

    # Convert to DataFrame
    df = pd.DataFrame([input_dict])

    # Scale
    df_scaled = pd.DataFrame(scaler.transform(df), columns=all_features)

    return df_scaled

# ── Routes ───────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        model_choice = data.get('model', 'rf')

        df_scaled = prepare_input(data)

        if model_choice == 'rf':
            features = rf_features
            model    = rf_model
        else:
            features = svm_features
            model    = svm_model

        # Filter to selected features
        df_filtered = df_scaled[features]

        # Predict
        prediction = model.predict(df_filtered)[0]

        # Color code result
        colors = {
            'Normal': 'green',
            'DoS'   : 'red',
            'Probe' : 'orange',
            'R2L'   : 'red',
            'U2R'   : 'red'
        }

        return jsonify({
            'prediction' : prediction,
            'color'      : colors.get(prediction, 'gray'),
            'model_used' : 'Random Forest' if model_choice == 'rf' else 'SVM',
            'status'     : 'success'
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)