# Clinicyou Encryption API

Python Flask API for encrypting payloads using the Clinicyou encryption scheme (AES-CBC with PBKDF2-MD5).

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

The API will be available at `http://localhost:5000`

## Deploy to Railway

1. **Create a new GitHub repo** (if you don't have one):
   - Go to https://github.com/new
   - Name it `clinicyou-encryption-api` or similar
   - Don't initialize with README/gitignore (we have those)

2. **Push this code to GitHub**:
   ```bash
   cd "/Users/jamesosullivan/Documents/Bubble DB work"
   git init
   git add .
   git commit -m "Initial commit: Encryption API"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/clinicyou-encryption-api.git
   git push -u origin main
   ```

3. **Deploy to Railway**:
   - Go to https://railway.app
   - Click "New Project" → "Deploy from GitHub"
   - Select your repo
   - Railway will auto-detect it's a Python app and deploy
   - Get your URL from the Railway dashboard

## API Endpoints

### POST `/encrypt`

Encrypt a payload.

**Request:**
```json
{
    "payload": {
        "appname": "clinicyou",
        "app_version": "519t7",
        "type": "custom.patient",
        "constraints": [...],
        "sorts_list": [],
        "from": 0,
        "search_path": "...",
        "situation": "initial search",
        "n": 93
    }
}
```

**Response:**
```json
{
    "success": true,
    "x": "base64_string",
    "y": "base64_string",
    "z": "base64_string",
    "timestamp_ms": "1767082236020",
    "raw_iv_hex": "f911a851e3fd42961be3f04ddb23bc85"
}
```

### GET `/health`

Health check.

**Response:**
```json
{
    "status": "ok"
}
```

### GET `/`

API documentation.

## Example Usage

```bash
curl -X POST https://your-railway-url.railway.app/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "appname": "clinicyou",
      "type": "test"
    }
  }'
```

## Environment Variables

None required for basic operation.

## Files

- `app.py` - Flask application
- `encrypt_working.py` - Encryption logic
- `requirements.txt` - Python dependencies
- `Procfile` - Railway deployment configuration
