from flask import Flask, request, jsonify, render_template
import os
import zipfile
import re
import tempfile
import shutil
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── ML dependencies ────────────────────────────────────────────────────────
try:
    import joblib
    import numpy as np
    import pandas as pd
    ML_LIBS = True
except ImportError:
    ML_LIBS = False

MODEL = None
FEATURE_LIST = None
MODEL_LOAD_ERROR = None

# ── Exact 34 features the model was trained on ────────────────────────────
# These are SHORT names (no android.permission. prefix)
PERM_FEATURES = [
    'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS',
    'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'RECORD_AUDIO', 'CAMERA',
    'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CALL_PHONE', 'PROCESS_OUTGOING_CALLS',
    'READ_PHONE_STATE', 'RECEIVE_BOOT_COMPLETED', 'INTERNET',
    'ACCESS_NETWORK_STATE', 'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE',
    'GET_ACCOUNTS', 'USE_CREDENTIALS', 'INSTALL_PACKAGES', 'DELETE_PACKAGES',
    'MOUNT_UNMOUNT_FILESYSTEMS', 'CHANGE_WIFI_STATE', 'DISABLE_KEYGUARD',
    'WAKE_LOCK', 'SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN',
]
# + 5 structural features:
# num_activities, num_services, num_receivers, num_providers, total_perms

DANGEROUS = {
    'SEND_SMS', 'READ_SMS', 'RECEIVE_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
    'PROCESS_OUTGOING_CALLS', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION',
    'RECORD_AUDIO', 'SYSTEM_ALERT_WINDOW', 'RECEIVE_BOOT_COMPLETED',
    'WRITE_EXTERNAL_STORAGE', 'CAMERA', 'READ_PHONE_STATE',
    'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'BIND_DEVICE_ADMIN',
    'MOUNT_UNMOUNT_FILESYSTEMS', 'CALL_PHONE',
}


# ── Load model ─────────────────────────────────────────────────────────────
def load_model():
    global MODEL, FEATURE_LIST, MODEL_LOAD_ERROR
    if not ML_LIBS:
        MODEL_LOAD_ERROR = "ML libraries not installed"
        return False

    search_pairs = [
        ('malware_model.pkl', 'feature_columns.pkl'),
        ('malware_model.pkl', 'features.pkl'),
        ('/app/malware_model.pkl', '/app/feature_columns.pkl'),
        ('/app/malware_model.pkl', '/app/features.pkl'),
        (r'D:\apktool\malware_model.pkl', r'D:\apktool\feature_columns.pkl'),
    ]

    for model_path, feat_path in search_pairs:
        if os.path.exists(model_path):
            try:
                MODEL = joblib.load(model_path)
                if os.path.exists(feat_path):
                    FEATURE_LIST = joblib.load(feat_path)
                else:
                    FEATURE_LIST = list(getattr(MODEL, 'feature_names_in_', PERM_FEATURES))
                print(f"[OK] Model loaded: expects {MODEL.n_features_in_} features")
                print(f"[OK] Feature list: {FEATURE_LIST}")
                return True
            except Exception as e:
                MODEL_LOAD_ERROR = str(e)
                print(f"[!] Load error: {e}")
                return False

    MODEL_LOAD_ERROR = "malware_model.pkl not found"
    return False


# ── Binary manifest parser (UTF-16LE scan) ────────────────────────────────
def parse_binary_manifest(data):
    """Extract SHORT permission names from binary AndroidManifest.xml."""
    found = []
    all_perms = PERM_FEATURES + [
        'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
        'ACCESS_WIFI_STATE', 'VIBRATE', 'FLASHLIGHT',
    ]
    for perm in all_perms:
        # Try short name
        if perm.encode('utf-16-le') in data:
            if perm not in found:
                found.append(perm)
            continue
        # Try full name
        full = f'android.permission.{perm}'.encode('utf-16-le')
        if full in data:
            if perm not in found:
                found.append(perm)
    return found


def count_components_binary(data):
    """Count activities/services/receivers/providers from binary manifest."""
    counts = {
        'num_activities': 0,
        'num_services': 0,
        'num_receivers': 0,
        'num_providers': 0,
    }
    tags = {
        'activity': 'num_activities',
        'service': 'num_services',
        'receiver': 'num_receivers',
        'provider': 'num_providers',
    }
    for tag, key in tags.items():
        needle = tag.encode('utf-16-le')
        counts[key] = data.count(needle)
    return counts


# ── Main feature extraction ────────────────────────────────────────────────
def extract_features_from_apk(apk_path):
    """
    Extract the exact 34 features the model was trained on:
    29 permission flags + num_activities + num_services +
    num_receivers + num_providers + total_perms
    """
    features = {p: 0 for p in PERM_FEATURES}
    features.update({
        'num_activities': 0,
        'num_services': 0,
        'num_receivers': 0,
        'num_providers': 0,
        'total_perms': 0,
    })

    found_perms = []
    num_files = 0
    num_dex = 0
    has_native = False
    has_assets = False

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            num_files = len(names)
            num_dex = sum(1 for n in names if n.endswith('.dex'))
            has_native = any('lib/' in n for n in names)
            has_assets = any('assets/' in n for n in names)

            if 'AndroidManifest.xml' in names:
                manifest_data = z.read('AndroidManifest.xml')

                # Extract permissions
                found_perms = parse_binary_manifest(manifest_data)
                for p in found_perms:
                    if p in features:
                        features[p] = 1

                # Count components
                comp = count_components_binary(manifest_data)
                features.update(comp)

                features['total_perms'] = len(found_perms)

    except Exception as e:
        print(f"[!] Feature extraction error: {e}")
        return None, [], num_files, num_dex, has_native, has_assets

    return features, found_perms, num_files, num_dex, has_native, has_assets


# ── Routes ─────────────────────────────────────────────────────────────────
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
        features, found_perms, num_files, num_dex, has_native, has_assets = \
            extract_features_from_apk(save_path)

        if features is None:
            return jsonify({'error': 'Could not parse APK. It may be corrupted.'}), 400

        dangerous_found = [p for p in found_perms if p in DANGEROUS]

        # ── ML prediction ─────────────────────────────────────────────────
        model_used = False
        label = 'BENIGN'
        confidence = 80.0
        benign_pct = 80.0
        malware_pct = 20.0

        if MODEL is not None and FEATURE_LIST is not None:
            try:
                # Build vector in exact order model expects
                vector = [features.get(col, 0) for col in FEATURE_LIST]
                pred = MODEL.predict([vector])[0]
                proba = MODEL.predict_proba([vector])[0]
                label = 'MALWARE' if pred == 1 else 'BENIGN'
                benign_pct = float(proba[0]) * 100
                malware_pct = float(proba[1]) * 100
                confidence = float(max(proba)) * 100
                model_used = True
                print(f"[OK] {label} ({confidence:.1f}%) | perms={len(found_perms)} | dangerous={len(dangerous_found)}")
            except Exception as e:
                print(f"[!] Prediction error: {e}")

        if not model_used:
            # Heuristic fallback
            score = len(dangerous_found) * 8 + num_dex * 5 + (10 if has_native else 0)
            score = min(score, 95)
            if score > 45:
                label, malware_pct, benign_pct, confidence = 'MALWARE', float(score), 100.0 - score, float(score)
            else:
                label, benign_pct, malware_pct, confidence = 'BENIGN', float(100 - score), float(score), float(100 - score)

        # Risk level
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
            'permissions': found_perms,
            'dangerous': dangerous_found,
            'num_files': num_files,
            'num_dex': num_dex,
            'has_native': has_native,
            'has_assets': has_assets,
            'total_perms': len(found_perms),
            'model_used': model_used,
            'model_error': None if model_used else MODEL_LOAD_ERROR,
        })

    finally:
        try:
            os.remove(save_path)
        except Exception:
            pass


load_model()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
