from flask import Flask, request, jsonify
from encrypt_working import encrypt_payload
import json

app = Flask(__name__)

APPNAME = "clinicyou"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt a payload

    Request body:
    {
        "payload": { ... },
        "timestamp_ms": 1234567890 (optional),
        "custom_iv_hex": "abc123..." (optional)
    }

    Response:
    {
        "success": true,
        "x": "base64...",
        "y": "base64...",
        "z": "base64...",
        "timestamp_ms": "1234567890",
        "raw_iv_hex": "abc123..."
    }
    """
    try:
        data = request.get_json()

        if not data or 'payload' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "payload" field in request body'
            }), 400

        payload = data['payload']
        timestamp_ms = data.get('timestamp_ms')
        custom_iv = data.get('custom_iv_hex')

        # Convert custom_iv from hex if provided
        raw_iv = None
        if custom_iv:
            raw_iv = bytes.fromhex(custom_iv)

        # Encrypt
        x, y, z, timestamp_result, raw_iv_result = encrypt_payload(
            APPNAME,
            payload,
            timestamp_ms=timestamp_ms,
            raw_iv=raw_iv
        )

        return jsonify({
            'success': True,
            'x': x,
            'y': y,
            'z': z,
            'timestamp_ms': timestamp_result,
            'raw_iv_hex': raw_iv_result.hex()
        }), 200

    except json.JSONDecodeError:
        return jsonify({
            'success': False,
            'error': 'Invalid JSON in request body'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        'name': 'Clinicyou Encryption API',
        'endpoints': {
            'POST /encrypt': 'Encrypt a payload',
            'GET /health': 'Health check'
        },
        'example': {
            'request': {
                'payload': {
                    'appname': 'clinicyou',
                    'type': 'test'
                }
            },
            'response': {
                'success': True,
                'x': 'base64...',
                'y': 'base64...',
                'z': 'base64...',
                'timestamp_ms': '1234567890',
                'raw_iv_hex': 'abc123...'
            }
        }
    }), 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
