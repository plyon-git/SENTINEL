# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import tempfile

from flask import request, jsonify, send_from_directory

from backend.config import Config
from backend.schema_mapper import SchemaMapper
from backend.fraud_detector import FraudDetector
from backend.csv_reader import read_csv_chunked


logger = logging.getLogger('ledgewell-sentinel')

current_mode = {'demo': False}


def _save_upload_to_tempfile(file_storage):
    """Save an uploaded FileStorage to a NamedTemporaryFile. Returns the path."""
    # delete=False so we keep the file across the close; we manually unlink in finally.
    tmp = tempfile.NamedTemporaryFile(suffix='.csv', delete=False)
    try:
        file_storage.save(tmp.name)
    finally:
        tmp.close()
    return tmp.name


def _safe_unlink(path):
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        # Best-effort cleanup — don't crash the request because tmp removal failed.
        logger.debug("Could not remove temp file %s", path, exc_info=True)


def register_routes(app):
    @app.route('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'File must be a CSV'}), 400

        tmp_path = None
        try:
            tmp_path = _save_upload_to_tempfile(file)
            df = read_csv_chunked(tmp_path, Config.CHUNK_SIZE)

            if df.is_empty():
                return jsonify({'error': 'The CSV file is empty'}), 400

            mapper = SchemaMapper(df)
            mapped_df, mapping_report = mapper.map()

            detector = FraudDetector(mapped_df, mapping_report)
            result = detector.run_analysis()
            return jsonify(result)

        except Exception as e:
            logger.exception("Error processing upload")
            return jsonify({'error': f'Server error: {str(e)}'}), 500
        finally:
            _safe_unlink(tmp_path)

    @app.route('/mapping/preview', methods=['POST'])
    def preview_mapping():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        tmp_path = None
        try:
            tmp_path = _save_upload_to_tempfile(file)
            df = read_csv_chunked(tmp_path, Config.CHUNK_SIZE)

            mapper = SchemaMapper(df)
            _, mapping_report = mapper.map()
            return jsonify(mapping_report)
        except Exception as e:
            logger.exception("Error in mapping preview")
            return jsonify({'error': str(e)}), 500
        finally:
            _safe_unlink(tmp_path)

    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'version': '7.0.1', 'engine': 'Polars'})

    @app.route('/config', methods=['GET', 'POST'])
    def config_endpoint():
        if request.method == 'GET':
            return jsonify({
                'velocity_window_minutes': Config.VELOCITY_WINDOW_MINUTES,
                'velocity_min_attempts': Config.VELOCITY_MIN_ATTEMPTS,
                'velocity_max_avg_value': Config.VELOCITY_MAX_AVG_VALUE,
                'ato_window_hours': Config.ATO_WINDOW_HOURS,
                'bin_attack_ip_min': Config.BIN_ATTACK_IP_MIN,
                'bin_attack_card_min': Config.BIN_ATTACK_CARD_MIN,
                'chunk_size': Config.CHUNK_SIZE,
                'grade_thresholds': Config.GRADE_THRESHOLDS,
            })
        # POST
        data = request.get_json(silent=True) or {}
        for key, value in data.items():
            if hasattr(Config, key.upper()):
                setattr(Config, key.upper(), value)
        return jsonify({'status': 'updated'})

    @app.route('/set_mode', methods=['POST'])
    def set_mode():
        data = request.get_json(silent=True) or {}
        if 'demo_mode' not in data:
            return jsonify({'error': 'Missing demo_mode'}), 400

        demo = bool(data['demo_mode'])
        current_mode['demo'] = demo

        if demo:
            Config.VELOCITY_MIN_ATTEMPTS = 3
            Config.VELOCITY_MAX_AVG_VALUE = 30.0
            Config.BIN_ATTACK_IP_MIN = 5
            Config.BIN_ATTACK_CARD_MIN = 4
            Config.DEVICE_MANY_USERS_THRESHOLD = 10
            Config.RISK_WEIGHTS.update({
                'card_testing': 5,
                'ato_attempt': 4,
                'bin_attack': 3,
                'vpn_ip': 2,
                'device_shared': 2,
            })
            Config.GRADE_THRESHOLDS.update({
                'CRITICAL RISK': 5,
                'INVESTIGATE': 3,
                'HIGH RISK': 1,
            })
        else:
            Config.VELOCITY_MIN_ATTEMPTS = 5
            Config.VELOCITY_MAX_AVG_VALUE = 20.0
            Config.BIN_ATTACK_IP_MIN = 10
            Config.BIN_ATTACK_CARD_MIN = 8
            Config.DEVICE_MANY_USERS_THRESHOLD = 20
            Config.RISK_WEIGHTS.update({
                'card_testing': 4,
                'ato_attempt': 3,
                'bin_attack': 2,
                'vpn_ip': 1,
                'device_shared': 1,
            })
            Config.GRADE_THRESHOLDS.update({
                'CRITICAL RISK': 6,
                'INVESTIGATE': 4,
                'HIGH RISK': 2,
            })

        logger.info(f"Demo mode set to: {demo}")
        return jsonify({'demo_mode': demo})
