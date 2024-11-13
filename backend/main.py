import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from modules import network_scan
import json

logging.basicConfig(
    level=logging.INFO,  # Set the base log level
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Logs to console
        logging.FileHandler("app.log")  # Logs to a file named app.log
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Render the main page
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Step 1: Network Scan
@app.post("/scan")
async def start_scan(
    request: Request,
    ip_range: str = Form(...),
    service_version: Optional[bool] = Form(False),
    os_detection: Optional[bool] = Form(False),
    aggressive: Optional[bool] = Form(False),
    tcp_scan: Optional[bool] = Form(False),
    udp_scan: Optional[bool] = Form(False),
    ping_scan: Optional[bool] = Form(False),
    fast_scan: Optional[bool] = Form(False),
    port_range: Optional[str] = Form(""),
    script: Optional[List[str]] = Form(None),
    max_rtt_timeout: Optional[str] = Form(""),
    host_timeout: Optional[str] = Form(""),
    retries: Optional[int] = Form(3),
    scan_delay: Optional[str] = Form("")
):
    options = {
        "service_version": service_version,
        "os_detection": os_detection,
        "aggressive": aggressive,
        "tcp_scan": tcp_scan,
        "udp_scan": udp_scan,
        "ping_scan": ping_scan,
        "fast_scan": fast_scan,
        "port_range": port_range or "",
        "scripts": script or [],
        "max_rtt_timeout": max_rtt_timeout or "",
        "host_timeout": host_timeout or "",
        "retries": retries,
        "scan_delay": scan_delay or "",
        "output_format": "normal"
    }

    # Run the Nmap scan with user-defined options
    scan_results = network_scan.run_nmap_scan(ip_range, options)
    
    # Render the template with scan results
    return templates.TemplateResponse("index.html", {"request": request, "scan_results": scan_results})

