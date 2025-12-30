from hashlib import pbkdf2_hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json
import os
import time

appname = "clinicyou"

def pad_data(data):
    """Add PKCS7 padding"""
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def encode_with_fixed_key_and_iv(appname, plaintext, custom_iv, add_padding=True):
    """Encrypt data using PBKDF2-derived key and IV"""
    plaintext_padded = pad_data(plaintext) if add_padding else plaintext
    derived_iv = pbkdf2_hmac('md5', custom_iv.encode('utf-8'), appname.encode('utf-8'), 7, dklen=16)
    derived_key = pbkdf2_hmac('md5', appname.encode('utf-8'), appname.encode('utf-8'), 7, dklen=32)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(plaintext_padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def encrypt_payload(appname, plaintext_dict, timestamp_ms=None, raw_iv=None):
    """
    Encrypt a payload following the clinicyou encryption scheme

    Args:
        appname: Application name (e.g., "clinicyou")
        plaintext_dict: Dictionary to encrypt
        timestamp_ms: Timestamp in milliseconds (default: current time)
        raw_iv: Raw IV bytes (default: 16 random bytes, avoiding 0x0e, 0x0d, 0x0f)

    Returns:
        Tuple of (x, y, z) base64-encoded encrypted values
    """

    # Generate timestamp if not provided
    if timestamp_ms is None:
        timestamp_ms = str(int(time.time() * 1000))
    else:
        timestamp_ms = str(timestamp_ms)

    # Generate random IV if not provided (avoid problematic bytes)
    if raw_iv is None:
        # Generate random bytes but exclude 0x0e, 0x0d, 0x0f
        raw_iv = bytearray()
        while len(raw_iv) < 16:
            byte = os.urandom(1)[0]
            if byte not in [0x0e, 0x0d, 0x0f]:
                raw_iv.append(byte)
        raw_iv = bytes(raw_iv)
    elif isinstance(raw_iv, str):
        raw_iv = raw_iv.encode('utf-8')

    # Step 1: Encrypt the timestamp (y)
    # Timestamp needs to be appended with '_1' suffix
    timestamp_with_suffix = (timestamp_ms + '_1').encode('utf-8')
    y = encode_with_fixed_key_and_iv(appname, timestamp_with_suffix, 'po9')

    # Step 2: Encrypt the raw IV (x)
    x = encode_with_fixed_key_and_iv(appname, raw_iv, 'fl1')

    # Step 3: Derive keys for payload encryption
    # Note: When decrypting x, certain bytes are removed. We use the cleaned version here.
    raw_iv_cleaned = raw_iv.replace(b'\x0e', b'').replace(b'\r', b'').replace(b'\x0f', b'')

    key_combined = f"{appname}{timestamp_ms}".encode('utf-8').replace(b'\x01', b'')
    derived_key = pbkdf2_hmac('md5', key_combined, appname.encode('utf-8'), 7, dklen=32)
    derived_iv = pbkdf2_hmac('md5', raw_iv_cleaned, appname.encode('utf-8'), 7, dklen=16)

    # Step 4: Encrypt the payload (z)
    plaintext_json = json.dumps(plaintext_dict, separators=(',', ':'))
    plaintext_bytes = plaintext_json.encode('utf-8')
    plaintext_padded = pad_data(plaintext_bytes)

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(plaintext_padded) + encryptor.finalize()
    z = base64.b64encode(encrypted_payload).decode('utf-8')

    return x, y, z, timestamp_ms, raw_iv

# Decrypt function for round-trip testing
def decode_with_fixed_key_and_iv(appname, ciphertext_b64, custom_iv):
    ciphertext = base64.b64decode(ciphertext_b64)
    derived_iv = pbkdf2_hmac('md5', custom_iv.encode('utf-8'), appname.encode('utf-8'), 7, dklen=16)
    derived_key = pbkdf2_hmac('md5', appname.encode('utf-8'), appname.encode('utf-8'), 7, dklen=32)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_padded

def unpad_data(padded_data):
    pad_length = padded_data[-1]
    return padded_data[:-pad_length]

def verify_encryption(appname, x, y, z):
    """Verify that encrypted values can be decrypted"""
    print("\n" + "="*70)
    print("VERIFICATION - Decrypting locally")
    print("="*70)

    try:
        # Decrypt y (timestamp)
        decoded_y_padded = decode_with_fixed_key_and_iv(appname, y, 'po9')
        # Smart unpadding: only unpad if we detect valid PKCS7 padding
        pad_len_y = decoded_y_padded[-1]
        if 0 < pad_len_y <= 16 and all(b == pad_len_y for b in decoded_y_padded[-pad_len_y:]):
            decoded_y = unpad_data(decoded_y_padded).decode('utf-8').replace('_1', '')
        else:
            decoded_y = decoded_y_padded.decode('utf-8').replace('_1', '')
        print(f"✓ Decrypted timestamp: {decoded_y}")

        # Decrypt x (IV)
        decoded_x_padded = decode_with_fixed_key_and_iv(appname, x, 'fl1')
        # Smart unpadding: only unpad if we detect valid PKCS7 padding
        pad_len_x = decoded_x_padded[-1]
        if 0 < pad_len_x <= 16 and all(b == pad_len_x for b in decoded_x_padded[-pad_len_x:]):
            decoded_x_unpadded = unpad_data(decoded_x_padded)
        else:
            decoded_x_unpadded = decoded_x_padded
        # Filter specific bytes
        decoded_x = decoded_x_unpadded.replace(b'\x0e', b'').replace(b'\r', b'').replace(b'\x0f', b'')
        print(f"✓ Decrypted IV (hex): {decoded_x.hex()}")

        # Derive keys
        key_combined = f"{appname}{decoded_y}".encode('utf-8').replace(b'\x01', b'')
        derived_key = pbkdf2_hmac('md5', key_combined, appname.encode('utf-8'), 7, dklen=32)
        derived_iv = pbkdf2_hmac('md5', decoded_x, appname.encode('utf-8'), 7, dklen=16)

        # Decrypt payload
        payload = base64.b64decode(z)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(payload) + decryptor.finalize()
        decrypted_data = unpad_data(decrypted_padded)

        # Try to parse
        result = json.loads(decrypted_data)
        print(f"✓ Successfully decrypted payload")
        print(f"✓ Payload type: {result.get('type')}")
        return True
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# Example usage
if __name__ == "__main__":
    # Create a test payload
    test_payload = {
        "appname": "clinicyou",
        "app_version": "519t7",
        "type": "custom.patient",
        "constraints": [
            {
                "key": "diagnoses_text",
                "constraint_type": "is_not_empty",
                "self": None
            }
        ],
        "sorts_list": [],
        "from": 0,
        "search_path": '{"constructor_name":"DataSource","args":[{"type":"json","value":"%p3.cnEQb0.%el.cnEQh0.%p.%ds"},{"type":"node","value":{"constructor_name":"Element","args":[{"type":"json","value":"%p3.cnEQb0.%el.cnEQh0"}]}},{"type":"raw","value":"Search"}]}',
        "situation": "initial search",
        "n": 93
    }

    # Encrypt
    x, y, z, timestamp_ms, raw_iv = encrypt_payload(appname, test_payload)

    print("="*70)
    print("ENCRYPTED PAYLOAD")
    print("="*70)
    print(f"Timestamp (ms): {timestamp_ms}")
    print(f"Raw IV (hex): {raw_iv.hex()}")
    print(f"\nEncrypted values:")
    print(f"x = \"{x}\"")
    print(f"y = \"{y}\"")
    print(f"z = \"{z}\"")

    # Verify locally
    verify_encryption(appname, x, y, z)

    print("\n" + "="*70)
    print("CURL REQUEST")
    print("="*70)
    print(f"""curl -X POST https://decrypt-worker.james-a7a.workers.dev \\
  -H "Content-Type: application/json" \\
  -d '{{"x": "{x}", "y": "{y}", "z": "{z}"}}'""")
