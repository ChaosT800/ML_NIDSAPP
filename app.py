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

# ── Column names ─────────────────────────────────────
col_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

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

# ── Helper: build full feature vector ───────────────
def prepare_input(form_data):
    input_dict = {col: 0 for col in all_features}

    for field in numerical_fields:
        if field in form_data:
            input_dict[field] = float(form_data[field])

    protocol = form_data.get('protocol_type', 'tcp')
    service  = form_data.get('service', 'http')
    flag     = form_data.get('flag', 'SF')

    if f'protocol_type_{protocol}' in input_dict:
        input_dict[f'protocol_type_{protocol}'] = 1
    if f'service_{service}' in input_dict:
        input_dict[f'service_{service}'] = 1
    if f'flag_{flag}' in input_dict:
        input_dict[f'flag_{flag}'] = 1

    df = pd.DataFrame([input_dict])
    df_scaled = pd.DataFrame(scaler.transform(df), columns=all_features)

    return df_scaled

# ── Helper: process single row ───────────────────────
def prepare_row(row):
    input_dict = {col: 0 for col in all_features}

    for field in numerical_fields:
        if field in row:
            input_dict[field] = float(row[field])

    protocol = str(row.get('protocol_type', 'tcp')).lower()
    service  = str(row.get('service', 'http')).lower()
    flag     = str(row.get('flag', 'SF'))

    if f'protocol_type_{protocol}' in input_dict:
        input_dict[f'protocol_type_{protocol}'] = 1
    if f'service_{service}' in input_dict:
        input_dict[f'service_{service}'] = 1
    if f'flag_{flag}' in input_dict:
        input_dict[f'flag_{flag}'] = 1

    row_df     = pd.DataFrame([input_dict])
    row_scaled = pd.DataFrame(
        scaler.transform(row_df), columns=all_features)

    return row_scaled

# ── Routes ───────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data         = request.get_json()
        model_choice = data.get('model', 'rf')

        df_scaled = prepare_input(data)

        if model_choice == 'rf':
            features = rf_features
            model    = rf_model
        else:
            features = svm_features
            model    = svm_model

        df_filtered = df_scaled[features]
        prediction  = model.predict(df_filtered)[0]

        colors = {
            'Normal': 'green',
            'DoS'   : 'red',
            'Probe' : 'orange',
            'R2L'   : 'red',
            'U2R'   : 'red'
        }

        return jsonify({
            'prediction': prediction,
            'color'     : colors.get(prediction, 'gray'),
            'model_used': 'Random Forest' if model_choice == 'rf' else 'SVM',
            'status'    : 'success'
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/predict_csv', methods=['POST'])
def predict_csv():
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file uploaded!'})

        file = request.files['file']

        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected!'})

        if not file.filename.endswith('.csv'):
            return jsonify({'status': 'error', 'message': 'Please upload a CSV file!'})

        # Read CSV
        df = pd.read_csv(file, header=None, nrows=500)

        # Assign column names based on shape
        if df.shape[1] == 43:
            df = df.iloc[:, :41]
            df.columns = col_names
        elif df.shape[1] == 42:
            df = df.iloc[:, :41]
            df.columns = col_names
        elif df.shape[1] == 41:
            df.columns = col_names
        else:
            return jsonify({
                'status' : 'error',
                'message': f'CSV has {df.shape[1]} columns — expected 41, 42 or 43!'
            })

        model_choice = request.args.get('model', 'rf')

        results = []
        for idx, row in df.iterrows():
            try:
                row_scaled = prepare_row(row)

                if model_choice == 'rf':
                    pred = rf_model.predict(row_scaled[rf_features])[0]
                else:
                    pred = svm_model.predict(row_scaled[svm_features])[0]

                colors = {
                    'Normal': 'green',
                    'DoS'   : 'red',
                    'Probe' : 'orange',
                    'R2L'   : 'red',
                    'U2R'   : 'red'
                }

                results.append({
                    'connection': idx + 1,
                    'prediction': pred,
                    'color'     : colors.get(pred, 'gray')
                })

            except Exception as e:
                results.append({
                    'connection': idx + 1,
                    'prediction': 'Error',
                    'color'     : 'gray'
                })

        # Summary counts
        summary = {}
        for r in results:
            pred = r['prediction']
            summary[pred] = summary.get(pred, 0) + 1

        return jsonify({
            'status' : 'success',
            'results': results,
            'summary': summary,
            'total'  : len(results)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
