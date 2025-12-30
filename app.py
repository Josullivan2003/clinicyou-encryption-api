from flask import Flask, request, jsonify
from encrypt_working import encrypt_payload, decode_with_fixed_key_and_iv, unpad_data
from hashlib import pbkdf2_hmac
import base64
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

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Decrypt a payload

    Request body:
    {
        "x": "base64...",
        "y": "base64...",
        "z": "base64..."
    }

    Response:
    {
        "success": true,
        "timestamp_ms": "1234567890",
        "data": { ... }
    }
    """
    try:
        data = request.get_json()

        if not data or 'x' not in data or 'y' not in data or 'z' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: x, y, z'
            }), 400

        x = data['x']
        y = data['y']
        z = data['z']

        # Decrypt y (timestamp)
        decoded_y_padded = decode_with_fixed_key_and_iv(APPNAME, y, 'po9')
        # Smart unpadding: only unpad if we detect valid PKCS7 padding
        pad_len_y = decoded_y_padded[-1]
        if 0 < pad_len_y <= 16 and all(b == pad_len_y for b in decoded_y_padded[-pad_len_y:]):
            decoded_y = unpad_data(decoded_y_padded).decode('utf-8').replace('_1', '')
        else:
            decoded_y = decoded_y_padded.decode('utf-8').replace('_1', '')

        # Decrypt x (IV)
        decoded_x_padded = decode_with_fixed_key_and_iv(APPNAME, x, 'fl1')
        # Smart unpadding: only unpad if we detect valid PKCS7 padding
        pad_len_x = decoded_x_padded[-1]
        if 0 < pad_len_x <= 16 and all(b == pad_len_x for b in decoded_x_padded[-pad_len_x:]):
            decoded_x_unpadded = unpad_data(decoded_x_padded)
        else:
            decoded_x_unpadded = decoded_x_padded
        # Remove specific bytes
        decoded_x = bytes(b for b in decoded_x_unpadded if b not in [0x0e, 0x0d, 0x0f])

        # Derive keys
        key_combined = f"{APPNAME}{decoded_y}".encode('utf-8').replace(b'\x01', b'')
        derived_key = pbkdf2_hmac('md5', key_combined, APPNAME.encode('utf-8'), 7, dklen=32)
        derived_iv = pbkdf2_hmac('md5', decoded_x, APPNAME.encode('utf-8'), 7, dklen=16)

        # Decrypt payload
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        payload = base64.b64decode(z)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(payload) + decryptor.finalize()
        decrypted_data = unpad_data(decrypted_padded)

        # Try to parse as JSON
        try:
            result = json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            result = decrypted_data.decode('utf-8')

        return jsonify({
            'success': True,
            'timestamp_ms': decoded_y,
            'data': result
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
            'POST /decrypt': 'Decrypt a payload',
            'GET /health': 'Health check'
        },
        'examples': {
            'encrypt': {
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
            },
            'decrypt': {
                'request': {
                    'x': 'base64...',
                    'y': 'base64...',
                    'z': 'base64...'
                },
                'response': {
                    'success': True,
                    'timestamp_ms': '1234567890',
                    'data': {
                        'appname': 'clinicyou',
                        'type': 'test'
                    }
                }
            }
        }
    }), 200

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
