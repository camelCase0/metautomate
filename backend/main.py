import datetime
import logging
import os
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, Form, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from modules import nmap_scan, script_manager
import json

logging.basicConfig(
    level=logging.INFO,  # Set the base log level
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Logs to console
        logging.FileHandler("app.log"),  # Logs to a file named app.log
    ],
)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

SCAN_RESULTS_DIR = "scan_results"
Path(SCAN_RESULTS_DIR).mkdir(exist_ok=True)


templates = Jinja2Templates(directory="templates")
network_scan = nmap_scan.NmapScanner()
script_mgr = script_manager.ScriptManager()


# Render the main page
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Scan endpoint
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
    scan_delay: Optional[str] = Form(""),
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
        "output_format": "normal",
    }

    scan_results = network_scan.run_scan(ip_range, options)
    current_time = datetime.datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

    scan_id = f"scan_{len(os.listdir(SCAN_RESULTS_DIR)) + 1}_{current_time}.json"
    scan_results_path = os.path.join(SCAN_RESULTS_DIR, scan_id)
    with open(scan_results_path, "w") as f:
        json.dump(scan_results, f)

    logger.info(f"Scan results saved to: {scan_results_path}")
    return JSONResponse({"message": "Scan completed", "scan_id": scan_id})

    # Render the template with scan results
    return templates.TemplateResponse(
        "index.html", {"request": request, "scan_results": scan_results}
    )


@app.get("/list-scans", response_class=JSONResponse)
async def list_scans():
    """
    Endpoint to list all saved scan results.
    """
    try:
        # Get all JSON files in the scan results directory
        scan_files = [
            file for file in os.listdir(SCAN_RESULTS_DIR) if file.endswith(".json")
        ]
        if not scan_files:
            return {"message": "No scans found."}

        return {"scans": scan_files}
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scans.")


@app.get("/view-scan/{scan_id}", response_class=HTMLResponse)
async def view_scan(request: Request, scan_id: str):
    """
    View a specific saved scan result in the browser.
    """
    try:
        scan_path = os.path.join(SCAN_RESULTS_DIR, scan_id)
        if not os.path.exists(scan_path):
            raise HTTPException(status_code=404, detail="Scan not found")

        with open(scan_path, "r") as f:
            scan_results = json.load(f)

        return templates.TemplateResponse(
            "index.html",
            {"request": request, "scan_id": scan_id, "scan_results": scan_results},
        )
    except Exception as e:
        logger.error(f"Failed to retrieve saved scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Upload script endpoint
@app.post("/upload-script")
async def upload_script(script: UploadFile = File(...)):
    """
    Endpoint to upload a custom Nmap script.
    """
    try:
        # Validate script file type
        if not script.filename.endswith(".nse"):
            raise HTTPException(
                status_code=400, detail="Only Nmap scripts (*.nse) are allowed."
            )

        # Save the uploaded script
        destination_path = script_mgr.upload_script(script.file, script.filename)
        logger.info(f"Uploaded script saved to: {destination_path}")
        return {"message": "Script uploaded successfully", "path": destination_path}

    except Exception as e:
        logger.error(f"Script upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# List scripts endpoint
@app.get("/scripts")
async def list_scripts():
    """
    Endpoint to list all available custom scripts.
    """
    try:
        scripts = script_mgr.list_scripts()
        return {"scripts": scripts}
    except Exception as e:
        logger.error(f"Failed to list scripts: {e}")
        raise HTTPException(status_code=500, detail=str(e))
