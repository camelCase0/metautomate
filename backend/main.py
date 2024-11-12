import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from modules import network_scan, vuln_scan, exploit_attempt, report_gen
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

# Step 2: Vulnerability Detection
@app.post("/vulnerabilities")
async def detect_vulnerabilities(request: Request, scan_results: str = Form(...)):
    try:
        # Log the raw scan_results to confirm input
        logger.info(f"Raw scan_results received: {scan_results}")

        # Attempt to parse scan_results as JSON
        parsed_scan_results = json.loads(scan_results)

        # Log the parsed results to confirm correct structure
        logger.info(f"Parsed scan_results: {parsed_scan_results}")

        # Ensure the data is a list of dictionaries
        if not isinstance(parsed_scan_results, list):
            raise HTTPException(status_code=400, detail="Invalid format: Expected a list of dictionaries.")

        vuln_results = vuln_scan.run_nmap_vuln_scan(parsed_scan_results)
        logger.info("Vulnerability detection completed successfully")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return templates.TemplateResponse("index.html", {"request": request, "error": "Invalid JSON format in scan results"})
    except Exception as e:
        logger.error(f"Error during vulnerability detection: {e}")
        return templates.TemplateResponse("index.html", {"request": request, "error": "Vulnerability detection failed"})

    return templates.TemplateResponse("index.html", {"request": request, "scan_results": parsed_scan_results, "vuln_results": vuln_results})


# Step 3: Optional Exploit Attempt
@app.post("/exploit")
async def try_exploit(request: Request, ip: str = Form(...), port: int = Form(...)):
    exploit_results = exploit_attempt.exploit_host(ip, port)
    return templates.TemplateResponse("index.html", {"request": request, "exploit_results": exploit_results})

# Step 4: Generate Report
@app.get("/report", response_class=HTMLResponse)
async def generate_report(request: Request, vuln_results: list = Form(...)):
    report = report_gen.generate_report(vuln_results)
    return templates.TemplateResponse("report.html", {"request": request, "report": report})
