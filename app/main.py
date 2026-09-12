
import csv
import io
import ipaddress
import re
import time
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import (
    HTMLResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .scanner import PortScanner


# ============================================================
# PATH CONFIGURATION
# ============================================================

# Project root:
# E:\Tecolas\PsychoPort
BASE_DIR = Path(__file__).resolve().parent.parent

STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="PsychoPort",
    description="Real-Time Network Port Intelligence Dashboard",
    version="1.0.0",
)


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)


# ============================================================
# TEMPLATES
# ============================================================

templates = Jinja2Templates(
    directory=str(TEMPLATES_DIR)
)


# ============================================================
# ACTIVE SCANNERS
# ============================================================

active_scanners: dict[int, PortScanner] = {}


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target: str) -> str:
    """
    Validate an IP address or hostname.

    Only scan systems that you own or have explicit
    authorization to test.
    """

    target = str(target or "").strip()

    if not target:
        raise ValueError(
            "Target is required."
        )

    # --------------------------------------------------------
    # Remove accidental HTTP/HTTPS protocol
    # --------------------------------------------------------

    target = re.sub(
        r"^https?://",
        "",
        target,
        flags=re.IGNORECASE,
    )

    # --------------------------------------------------------
    # Remove URL path
    # --------------------------------------------------------

    target = target.split("/")[0]

    # --------------------------------------------------------
    # Remove hostname:port
    # --------------------------------------------------------

    if target.count(":") == 1:

        host, possible_port = target.rsplit(
            ":",
            1,
        )

        if possible_port.isdigit():
            target = host

    # --------------------------------------------------------
    # Maximum hostname length
    # --------------------------------------------------------

    if len(target) > 253:
        raise ValueError(
            "Invalid target."
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(target)

        return target

    except ValueError:
        pass

    # --------------------------------------------------------
    # HOSTNAME
    # --------------------------------------------------------

    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?$"
    )

    if not hostname_pattern.match(target):

        raise ValueError(
            "Invalid domain or IP address."
        )

    return target


# ============================================================
# PORT RANGE BUILDER
# ============================================================

def build_ports(
    mode: str,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> list[int]:

    mode = str(
        mode or "quick"
    ).lower().strip()

    # ========================================================
    # QUICK SCAN
    # ========================================================

    if mode == "quick":

        return [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            443,
            445,
            587,
            993,
            995,
            1433,
            1521,
            3306,
            3389,
            5432,
            5900,
            6379,
            8000,
            8080,
            8443,
            9200,
            27017,
        ]

    # ========================================================
    # STANDARD SCAN
    # ========================================================

    if mode == "standard":

        return list(
            range(
                1,
                1025,
            )
        )

    # ========================================================
    # CUSTOM SCAN
    # ========================================================

    if mode == "custom":

        if start is None or end is None:

            raise ValueError(
                "Custom range requires start and end ports."
            )

        try:

            start = int(start)
            end = int(end)

        except (
            TypeError,
            ValueError,
        ):

            raise ValueError(
                "Start and end ports must be numbers."
            )

        if not (
            1 <= start <= 65535
            and 1 <= end <= 65535
        ):

            raise ValueError(
                "Ports must be between 1 and 65535."
            )

        if start > end:

            raise ValueError(
                "Start port must be less than end port."
            )

        if end - start > 5000:

            raise ValueError(
                "Custom scan is limited to 5000 ports."
            )

        return list(
            range(
                start,
                end + 1,
            )
        )

    # ========================================================
    # INVALID MODE
    # ========================================================

    raise ValueError(
        "Invalid scan mode."
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "online",
        "service": "PsychoPort",
        "version": "1.0.0",
    }


# ============================================================
# HOMEPAGE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
async def homepage(
    request: Request,
):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


# ============================================================
# WEBSOCKET SCANNER
# ============================================================

@app.websocket("/ws/scan")
async def websocket_scan(
    websocket: WebSocket,
):

    await websocket.accept()

    scanner: Optional[PortScanner] = None
    scanner_id: Optional[int] = None

    try:

        # ====================================================
        # RECEIVE REQUEST
        # ====================================================

        data = await websocket.receive_json()

        if not isinstance(data, dict):

            raise ValueError(
                "Invalid scan request."
            )

        # ====================================================
        # TARGET
        # ====================================================

        target = validate_target(
            data.get(
                "target",
                "",
            )
        )

        # ====================================================
        # SCAN MODE
        # ====================================================

        mode = str(
            data.get(
                "mode",
                "quick",
            )
        ).lower().strip()

        # ====================================================
        # PORT RANGE
        # ====================================================

        start = data.get("start")
        end = data.get("end")

        ports = build_ports(
            mode=mode,
            start=start,
            end=end,
        )

        # ====================================================
        # CREATE SCANNER
        # ====================================================

        scanner = PortScanner(
            target=target,
            ports=ports,
            timeout=0.8,
            workers=100,
        )

        scanner_id = id(scanner)

        active_scanners[
            scanner_id
        ] = scanner

        start_time = time.perf_counter()

        # ====================================================
        # SCAN STARTED
        # ====================================================

        await websocket.send_json(
            {
                "type": "started",
                "target": target,
                "mode": mode,
                "ports": len(ports),
            }
        )

        # ====================================================
        # EVENT CALLBACK
        # ====================================================

        async def send_event(event):

            try:

                await websocket.send_json(
                    event
                )

            except Exception:

                # Client disconnected.
                if scanner:
                    scanner.stop()

        # ====================================================
        # RUN SCANNER
        # ====================================================

        await scanner.run(
            send_event
        )

        # ====================================================
        # SCAN DURATION
        # ====================================================

        duration = round(
            time.perf_counter()
            - start_time,
            2,
        )

        await websocket.send_json(
            {
                "type": "duration",
                "seconds": duration,
            }
        )

        # ====================================================
        # COMPLETED
        # ====================================================

        await websocket.send_json(
            {
                "type": "completed",
            }
        )

    # ========================================================
    # CLIENT DISCONNECTED
    # ========================================================

    except WebSocketDisconnect:

        if scanner:

            scanner.stop()

    # ========================================================
    # VALIDATION ERROR
    # ========================================================

    except ValueError as exc:

        try:

            await websocket.send_json(
                {
                    "type": "error",
                    "message": str(exc),
                }
            )

        except Exception:

            pass

    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as exc:

        try:

            await websocket.send_json(
                {
                    "type": "error",
                    "message": (
                        "Scanner error: "
                        f"{str(exc)}"
                    ),
                }
            )

        except Exception:

            pass

    # ========================================================
    # CLEANUP
    # ========================================================

    finally:

        if scanner:

            scanner.stop()

        if scanner_id is not None:

            active_scanners.pop(
                scanner_id,
                None,
            )


# ============================================================
# CSV REPORT
# ============================================================

@app.post("/report/csv")
async def csv_report(
    request: Request,
):

    # ========================================================
    # READ JSON
    # ========================================================

    try:

        data = await request.json()

    except Exception:

        return StreamingResponse(
            iter(
                [
                    "Invalid JSON request."
                ]
            ),
            media_type="text/plain",
            status_code=400,
        )

    # ========================================================
    # RESULTS
    # ========================================================

    results = data.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):

        results = []

    # ========================================================
    # CREATE CSV
    # ========================================================

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow(
        [
            "Port",
            "State",
            "Service",
            "Risk",
            "Latency (ms)",
            "Banner",
        ]
    )

    # ========================================================
    # ADD RESULTS
    # ========================================================

    for result in results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        writer.writerow(
            [
                result.get(
                    "port",
                    "",
                ),
                result.get(
                    "state",
                    "",
                ),
                result.get(
                    "service",
                    "",
                ),
                result.get(
                    "risk",
                    "",
                ),
                result.get(
                    "latency_ms",
                    "",
                ),
                result.get(
                    "banner",
                    "",
                ),
            ]
        )

    output.seek(0)

    # ========================================================
    # DOWNLOAD CSV
    # ========================================================

    return StreamingResponse(
        iter(
            [
                output.getvalue()
            ]
        ),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                "attachment; "
                "filename=psychoport-report.csv"
        },
    )


# ============================================================
# LOCAL DEVELOPMENT ENTRY POINT
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )

