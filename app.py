from flask import Flask, render_template, request, jsonify
import os
import sys
import time
import zipfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── Try importing ML dependencies ──────────────────────────────────────────
try:
    import joblib
    import pandas as pd
    import numpy as np
    from androguard.misc import AnalyzeAPK
    MODEL_AVAILABLE = True
except ImportError:
    MODEL_AVAILABLE = False

FEATURE_COLUMNS = None
MODEL = None

def load_model():
    global MODEL, FEATURE_COLUMNS
    model_path    = r'C:\apktool\malware_model.pkl'
    features_path = r'C:\apktool\features.pkl'
    # fallback for Linux/Mac dev
    if not os.path.exists(model_path):
        model_path    = 'malware_model.pkl'
        features_path = 'features.pkl'
    if os.path.exists(model_path) and MODEL_AVAILABLE:
        MODEL          = joblib.load(model_path)
        FEATURE_COLUMNS = joblib.load(features_path)
        return True
    return False

def extract_features_fast(apk_path):
    """Fast ZIP-based feature extraction (no Androguard deep analysis)"""
    import zipfile
    PERMISSIONS = [
        'INTERNET','READ_SMS','SEND_SMS','CAMERA','RECORD_AUDIO',
        'ACCESS_FINE_LOCATION','READ_CALL_LOG','WRITE_EXTERNAL_STORAGE',
        'RECEIVE_BOOT_COMPLETED','SYSTEM_ALERT_WINDOW','READ_CONTACTS',
        'PROCESS_OUTGOING_CALLS','READ_PHONE_STATE','CHANGE_WIFI_STATE',
        'ACCESS_COARSE_LOCATION','READ_EXTERNAL_STORAGE',
    ]
    features = {f'perm_{p}': 0 for p in PERMISSIONS}
    features['num_permissions'] = 0
    features['num_files']       = 0
    features['has_native_libs'] = 0
    features['has_assets']      = 0
    features['has_dex']         = 0
    features['num_dex_files']   = 0

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            features['num_files']       = len(names)
            features['has_native_libs'] = int(any('lib/' in f for f in names))
            features['has_assets']      = int(any('assets/' in f for f in names))
            features['has_dex']         = int(any(f.endswith('.dex') for f in names))
            features['num_dex_files']   = sum(1 for f in names if f.endswith('.dex'))
            if 'AndroidManifest.xml' in names:
                manifest = z.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                count = 0
                for perm in PERMISSIONS:
                    if perm in manifest:
                        features[f'perm_{perm}'] = 1
                        count += 1
                features['num_permissions'] = count
        return features
    except Exception as e:
        return None

def get_permissions_list(apk_path):
    """Return list of found permissions for display"""
    PERMISSIONS = [
        'INTERNET','READ_SMS','SEND_SMS','CAMERA','RECORD_AUDIO',
        'ACCESS_FINE_LOCATION','READ_CALL_LOG','WRITE_EXTERNAL_STORAGE',
        'RECEIVE_BOOT_COMPLETED','SYSTEM_ALERT_WINDOW','READ_CONTACTS',
        'PROCESS_OUTGOING_CALLS','READ_PHONE_STATE','CHANGE_WIFI_STATE',
        'ACCESS_COARSE_LOCATION','READ_EXTERNAL_STORAGE',
    ]
    found = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' in z.namelist():
                manifest = z.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                for perm in PERMISSIONS:
                    if perm in manifest:
                        found.append(perm)
    except:
        pass
    return found

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'apk' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['apk']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'File must be an APK'}), 400

    # Save file
    filename  = file.filename
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    # Get file size
    file_size = os.path.getsize(save_path)

    # Extract features
    features = extract_features_fast(save_path)
    if features is None:
        return jsonify({'error': 'Could not parse APK file. It may be corrupted.'}), 400

    # Get permissions list
    permissions = get_permissions_list(save_path)

    # Dangerous permissions
    DANGEROUS = {'READ_SMS','SEND_SMS','READ_CALL_LOG','PROCESS_OUTGOING_CALLS',
                 'READ_CONTACTS','ACCESS_FINE_LOCATION','RECORD_AUDIO',
                 'SYSTEM_ALERT_WINDOW','RECEIVE_BOOT_COMPLETED','WRITE_EXTERNAL_STORAGE'}
    dangerous_found = [p for p in permissions if p in DANGEROUS]

    # Try ML model prediction
    if MODEL is not None and FEATURE_COLUMNS is not None:
        df = pd.DataFrame([features])
        df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)
        pred  = MODEL.predict(df)[0]
        proba = MODEL.predict_proba(df)[0]
        label      = 'MALWARE' if pred == 1 else 'BENIGN'
        confidence = float(max(proba)) * 100
        benign_pct = float(proba[0]) * 100
        malware_pct = float(proba[1]) * 100
    else:
        # Heuristic fallback when model not loaded
        score = 0
        score += len(dangerous_found) * 8
        score += features.get('num_dex_files', 0) * 5
        score += 10 if features.get('has_native_libs') else 0
        score = min(score, 95)
        if score > 45:
            label = 'MALWARE'
            malware_pct = float(score)
            benign_pct  = 100 - malware_pct
            confidence  = malware_pct
        else:
            label = 'BENIGN'
            benign_pct  = float(100 - score)
            malware_pct = float(score)
            confidence  = benign_pct

    # Risk level
    if label == 'MALWARE':
        if confidence >= 90:
            risk = 'Critical'
        elif confidence >= 75:
            risk = 'High'
        else:
            risk = 'Medium'
    else:
        risk = 'Low' if len(dangerous_found) < 3 else 'Medium'

    # Clean up
    try:
        os.remove(save_path)
    except:
        pass

    return jsonify({
        'filename':        filename,
        'file_size':       f'{file_size / 1024:.1f} KB' if file_size < 1024*1024 else f'{file_size/1024/1024:.2f} MB',
        'label':           label,
        'confidence':      round(confidence, 2),
        'benign_pct':      round(benign_pct, 2),
        'malware_pct':     round(malware_pct, 2),
        'risk':            risk,
        'permissions':     permissions,
        'dangerous':       dangerous_found,
        'num_files':       features.get('num_files', 0),
        'num_dex':         features.get('num_dex_files', 0),
        'has_native':      bool(features.get('has_native_libs')),
        'has_assets':      bool(features.get('has_assets')),
        'total_perms':     features.get('num_permissions', 0),
        'model_used':      MODEL is not None,
    })

if __name__ == '__main__':
    load_model()
    app.run(debug=True, port=5000)
