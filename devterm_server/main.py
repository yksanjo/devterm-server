"""DevTerm Server - FastAPI with background tasks and worker queue."""

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import asyncio
import json
import base64
import urllib.parse
import hashlib
import uuid
import re
import secrets
import socket
import time
import io
import qrcode
import yaml
import xmltodict
import requests

app = FastAPI(
    title="DevTerm Server",
    description="Server edition with background tasks and async processing",
    version="1.0.0"
)

# In-memory job storage (in production, use Redis)
jobs: Dict[str, Dict[str, Any]] = {}

# === MODELS ===

class JsonRequest(BaseModel):
    data: str
    mode: Optional[str] = "format"

class EncodeRequest(BaseModel):
    data: str

class HashRequest(BaseModel):
    data: str

class PasswordRequest(BaseModel):
    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    special: bool = True

class QrRequest(BaseModel):
    data: str

class HttpRequest(BaseModel):
    url: str
    method: str = "GET"
    body: Optional[str] = ""

class CaseRequest(BaseModel):
    data: str
    case_type: str = "lower"

# === BACKGROUND TASKS ===

def run_json_format(data: str, mode: str) -> Dict[str, Any]:
    """Background JSON formatting"""
    try:
        parsed = json.loads(data)
        if mode == "minify":
            return {"success": True, "output": json.dumps(parsed, separators=(',', ':'))}
        return {"success": True, "output": json.dumps(parsed, indent=2)}
    except json.JSONDecodeError as e:
        return {"success": False, "error": str(e)}

def run_hash_all(data: str) -> Dict[str, Any]:
    """Background hashing"""
    return {
        "success": True,
        "output": {
            "md5": hashlib.md5(data.encode()).hexdigest(),
            "sha1": hashlib.sha1(data.encode()).hexdigest(),
            "sha256": hashlib.sha256(data.encode()).hexdigest(),
            "sha512": hashlib.sha512(data.encode()).hexdigest(),
        }
    }

def run_port_scan(host: str, start: int, end: int) -> Dict[str, Any]:
    """Background port scanning"""
    open_ports = []
    for port in range(start, min(end + 1, 10000)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        if sock.connect_ex((host, port)) == 0:
            open_ports.append(port)
        sock.close()
    return {"success": True, "output": {"host": host, "open_ports": open_ports}}

# === SYNC ENDPOINTS ===

@app.post("/api/json/format")
async def format_json(req: JsonRequest):
    """Format or minify JSON"""
    result = run_json_format(req.data, req.mode)
    if result.get("success"):
        return result
    raise HTTPException(status_code=400, detail=result.get("error"))

@app.post("/api/base64/encode")
async def base64_encode(req: EncodeRequest):
    """Base64 encode"""
    return {"success": True, "output": base64.b64encode(req.data.encode()).decode()}

@app.post("/api/base64/decode")
async def base64_decode(req: EncodeRequest):
    """Base64 decode"""
    try:
        return {"success": True, "output": base64.b64decode(req.data.encode()).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/url/encode")
async def url_encode(req: EncodeRequest):
    """URL encode"""
    return {"success": True, "output": urllib.parse.quote(req.data, safe='')}

@app.post("/api/url/decode")
async def url_decode(req: EncodeRequest):
    """URL decode"""
    return {"success": True, "output": urllib.parse.unquote(req.data)}

@app.post("/api/hash/md5")
async def hash_md5(req: HashRequest):
    """MD5 hash"""
    return {"success": True, "output": hashlib.md5(req.data.encode()).hexdigest()}

@app.post("/api/hash/sha256")
async def hash_sha256(req: HashRequest):
    """SHA-256 hash"""
    return {"success": True, "output": hashlib.sha256(req.data.encode()).hexdigest()}

@app.post("/api/hash/all")
async def hash_all(req: HashRequest):
    """All hashes (async)"""
    return run_hash_all(req.data)

@app.post("/api/password/generate")
async def generate_password(req: PasswordRequest):
    """Generate password"""
    chars = ''
    if req.uppercase: chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if req.lowercase: chars += 'abcdefghijklmnopqrstuvwxyz'
    if req.digits: chars += '0123456789'
    if req.special: chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not chars:
        raise HTTPException(status_code=400, detail="Select at least one character type")
    
    password = ''.join(secrets.choice(chars) for _ in range(req.length))
    return {"success": True, "output": password}

@app.get("/api/uuid/generate")
async def generate_uuid():
    """Generate UUID"""
    return {"success": True, "output": str(uuid.uuid4())}

@app.post("/api/http/request")
async def http_request(req: HttpRequest):
    """Make HTTP request"""
    try:
        kwargs = {"method": req.method, "url": req.url, "timeout": 30}
        if req.body and req.method in ["POST", "PUT"]:
            kwargs["data"] = req.body
        
        response = requests.request(**kwargs)
        return {
            "success": True,
            "output": {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:5000]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/dns/lookup")
async def dns_lookup(hostname: str):
    """DNS lookup"""
    try:
        ip = socket.gethostbyname(hostname)
        return {"success": True, "output": {"hostname": hostname, "ip": ip}}
    except socket.gaierror as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/port/scan")
async def port_scan(host: str = "localhost", start: int = 1, end: int = 1024):
    """Scan ports (async)"""
    result = run_port_scan(host, start, end)
    return result

@app.post("/api/case/convert")
async def convert_case(req: CaseRequest):
    """Convert case"""
    data = req.data
    if req.case_type == "upper":
        output = data.upper()
    elif req.case_type == "lower":
        output = data.lower()
    elif req.case_type == "title":
        output = data.title()
    elif req.case_type == "camel":
        words = re.findall(r'[A-Za-z]+', data)
        output = words[0].lower() + ''.join(w.capitalize() for w in words[1:])
    elif req.case_type == "snake":
        output = re.sub(r'[\W]+', '_', data).lower().strip('_')
    elif req.case_type == "kebab":
        output = re.sub(r'[\W]+', '-', data).lower().strip('-')
    else:
        output = data
    return {"success": True, "output": output}

@app.get("/api/timestamp")
async def get_timestamp():
    """Get timestamp"""
    now = time.time()
    return {
        "success": True,
        "output": {
            "unix": int(now),
            "unix_ms": int(now * 1000),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)),
        }
    }

@app.post("/api/qrcode/generate")
async def generate_qr(req: QrRequest):
    """Generate QR code"""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(req.data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return {"success": True, "image": f"data:image/png;base64,{img_str}"}

# === BACKGROUND TASK ENDPOINTS ===

@app.post("/api/jobs/json-format")
async def job_json_format(req: JsonRequest, background_tasks: BackgroundTasks):
    """Create background job for JSON formatting"""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "pending", "result": None}
    
    def task():
        result = run_json_format(req.data, req.mode)
        jobs[job_id] = {"status": "completed", "result": result}
    
    background_tasks.add_task(task)
    return {"success": True, "job_id": job_id, "status": "pending"}

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    """Get job status"""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]

# === WEBSOCKET FOR REAL-TIME ===

@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Process and echo back
            await websocket.send_text(f"Echo: {data}")
    except Exception:
        pass

@app.get("/")
async def root():
    """API root"""
    return {
        "name": "DevTerm Server",
        "version": "1.0.0",
        "features": ["async", "background_tasks", "websocket", "job_queue"],
        "endpoints": [
            "/api/json/format",
            "/api/hash/all",
            "/api/port/scan",
            "/api/jobs/{job_id}",
            "/ws",
        ]
    }

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()
