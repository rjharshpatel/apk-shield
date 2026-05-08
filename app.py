from flask import Flask, request, jsonify, render_template
import os
import zipfile
import struct
import re

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── Try importing ML dependencies ──────────────────────────────────────────
try:
    import joblib
    import pandas as pd
    import numpy as np
    ML_LIBS = True
except ImportError:
    ML_LIBS = False

MODEL = None
FEATURE_COLUMNS = None
MODEL_LOAD_ERROR = None

PERMISSIONS = [
    'INTERNET', 'READ_SMS', 'SEND_SMS', 'CAMERA', 'RECORD_AUDIO',
    'ACCESS_FINE_LOCATION', 'READ_CALL_LOG', 'WRITE_EXTERNAL_STORAGE',
    'RECEIVE_BOOT_COMPLETED', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS',
    'PROCESS_OUTGOING_CALLS', 'READ_PHONE_STATE', 'CHANGE_WIFI_STATE',
    'ACCESS_COARSE_LOCATION', 'READ_EXTERNAL_STORAGE',
]

DANGEROUS = {
    'READ_SMS', 'SEND_SMS', 'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
    'READ_CONTACTS', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO',
    'SYSTEM_ALERT_WINDOW', 'RECEIVE_BOOT_COMPLETED', 'WRITE_EXTERNAL_STORAGE'
}

# ── FIX 1: Load model at module level so Gunicorn picks it up ──────────────
def load_model():
    global MODEL, FEATURE_COLUMNS, MODEL_LOAD_ERROR
    if not ML_LIBS:
        MODEL_LOAD_ERROR = "ML libraries not installed (joblib/pandas/numpy)"
        return False

    # Search multiple locations
    search_paths = [
        ('malware_model.pkl', 'features.pkl'),
        ('/app/malware_model.pkl', '/app/features.pkl'),
        (r'C:\apktool\malware_model.pkl', r'C:\apktool\features.pkl'),
    ]
    for model_path, features_path in search_paths:
        if os.path.exists(model_path):
            try:
                MODEL = joblib.load(model_path)
                if os.path.exists(features_path):
                    FEATURE_COLUMNS = joblib.load(features_path)
                else:
                    # If features.pkl missing, derive from model
                    FEATURE_COLUMNS = getattr(MODEL, 'feature_names_in_', None)
                return True
            except Exception as e:
                MODEL_LOAD_ERROR = str(e)
                return False

    MODEL_LOAD_ERROR = "malware_model.pkl not found"
    return False

# ── FIX 2: Parse binary AndroidManifest.xml properly ──────────────────────
def parse_binary_manifest(data):
    """
    Extract permission strings from APK's binary XML AndroidManifest.xml.
    APK manifests are AXML (Android Binary XML), NOT plain text.
    We scan for UTF-16LE strings which is how AXML stores string pool entries.
    """
    found_perms = []
    try:
        # Method: scan the binary for known permission substrings encoded as UTF-16LE
        # AXML string pool stores strings as UTF-16LE
        for perm in PERMISSIONS:
            # Encode permission name as UTF-16LE bytes (as it appears in AXML string pool)
            needle = perm.encode('utf-16-le')
            if needle in data:
                found_perms.append(perm)
            else:
                # Also try full permission string e.g. android.permission.INTERNET
                full = f'android.permission.{perm}'.encode('utf-16-le')
                if full in data:
                    found_perms.append(perm)
    except Exception:
        pass
    return found_perms


def extract_features(apk_path):
    """Extract features from APK using ZIP + binary manifest parsing."""
    features = {f'perm_{p}': 0 for p in PERMISSIONS}
    features.update({
        'num_permissions': 0,
        'num_files': 0,
        'has_native_libs': 0,
        'has_assets': 0,
        'has_dex': 0,
        'num_dex_files': 0,
    })

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            features['num_files'] = len(names)
            features['has_native_libs'] = int(any('lib/' in f for f in names))
            features['has_assets'] = int(any('assets/' in f for f in names))
            features['has_dex'] = int(any(f.endswith('.dex') for f in names))
            features['num_dex_files'] = sum(1 for f in names if f.endswith('.dex'))

            if 'AndroidManifest.xml' in names:
                manifest_data = z.read('AndroidManifest.xml')
                found_perms = parse_binary_manifest(manifest_data)
                for perm in found_perms:
                    features[f'perm_{perm}'] = 1
                features['num_permissions'] = len(found_perms)

        return features
    except Exception as e:
        return None


def get_permissions_list(apk_path):
    """Return list of permission names found in the APK manifest."""
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' in z.namelist():
                manifest_data = z.read('AndroidManifest.xml')
                return parse_binary_manifest(manifest_data)
    except Exception:
        pass
    return []


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'apk' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['apk']
    if not file.filename or not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'File must be an APK'}), 400

    filename = file.filename
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)
    file_size = os.path.getsize(save_path)

    try:
        features = extract_features(save_path)
        if features is None:
            return jsonify({'error': 'Could not parse APK. It may be corrupted.'}), 400

        permissions = get_permissions_list(save_path)
        dangerous_found = [p for p in permissions if p in DANGEROUS]

        # ── Prediction ────────────────────────────────────────────────────
        model_used = False
        if MODEL is not None and FEATURE_COLUMNS is not None and ML_LIBS:
            try:
                df = pd.DataFrame([features])
                df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)
                pred = MODEL.predict(df)[0]
                proba = MODEL.predict_proba(df)[0]
                label = 'MALWARE' if pred == 1 else 'BENIGN'
                benign_pct = float(proba[0]) * 100
                malware_pct = float(proba[1]) * 100
                confidence = float(max(proba)) * 100
                model_used = True
            except Exception as e:
                # ML failed, fall through to heuristic
                model_used = False

        if not model_used:
            # Heuristic fallback
            score = 0
            score += len(dangerous_found) * 8
            score += features.get('num_dex_files', 0) * 5
            score += 10 if features.get('has_native_libs') else 0
            score = min(score, 95)

            if score > 45:
                label = 'MALWARE'
                malware_pct = float(score)
                benign_pct = 100.0 - malware_pct
                confidence = malware_pct
            else:
                label = 'BENIGN'
                benign_pct = float(100 - score)
                malware_pct = float(score)
                confidence = benign_pct

        # ── Risk level ────────────────────────────────────────────────────
        if label == 'MALWARE':
            risk = 'Critical' if confidence >= 90 else ('High' if confidence >= 75 else 'Medium')
        else:
            risk = 'Low' if len(dangerous_found) < 3 else 'Medium'

        size_str = (f'{file_size/1024:.1f} KB' if file_size < 1024*1024
                    else f'{file_size/1024/1024:.2f} MB')

        return jsonify({
            'filename': filename,
            'file_size': size_str,
            'label': label,
            'confidence': round(confidence, 2),
            'benign_pct': round(benign_pct, 2),
            'malware_pct': round(malware_pct, 2),
            'risk': risk,
            'permissions': permissions,
            'dangerous': dangerous_found,
            'num_files': features.get('num_files', 0),
            'num_dex': features.get('num_dex_files', 0),
            'has_native': bool(features.get('has_native_libs')),
            'has_assets': bool(features.get('has_assets')),
            'total_perms': features.get('num_permissions', 0),
            'model_used': model_used,
            'model_error': None if model_used else MODEL_LOAD_ERROR,
        })

    finally:
        try:
            os.remove(save_path)
        except Exception:
            pass


# ── FIX 1: Call load_model() at module level (works with Gunicorn) ─────────
load_model()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
