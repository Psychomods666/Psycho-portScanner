import csv
import io
import ipaddress
import re
import socket
import time

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


app = FastAPI(
    title="PsychoPort",
    description="Real-Time Network Port Intelligence Dashboard",
    version="1.0.0",
)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)

templates = Jinja2Templates(
    directory="templates"
)


active_scanners = {}


# ---------------------------------------------------------
# Target validation
# ---------------------------------------------------------

def validate_target(target: str) -> str:

    target = target.strip()

    if not target:
        raise ValueError("Target is required.")

    # Remove accidental protocol
    target = re.sub(
        r"^https?://",
        "",
        target,
        flags=re.IGNORECASE,
    )

    # Remove path
    target = target.split("/")[0]

    if len(target) > 253:
        raise ValueError("Invalid target.")

    # IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Basic hostname validation
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
        raise ValueError("Invalid domain or IP address.")

    return target


# ---------------------------------------------------------
# Port ranges
# ---------------------------------------------------------

def build_ports(
    mode: str,
    start: int | None = None,
    end: int | None = None,
):

    if mode == "quick":

        ports = [
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

        return ports

    if mode == "standard":

        return list(range(1, 1025))

    if mode == "custom":

        if start is None or end is None:
            raise ValueError(
                "Custom range requires start and end ports."
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

        return list(range(start, end + 1))

    raise ValueError("Invalid scan mode.")


# ---------------------------------------------------------
# Homepage
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )

# ---------------------------------------------------------
# WebSocket scanner
# ---------------------------------------------------------

@app.websocket("/ws/scan")
async def websocket_scan(
    websocket: WebSocket,
):

    await websocket.accept()

    scanner = None

    try:

        data = await websocket.receive_json()

        target = validate_target(
            data.get("target", "")
        )

        mode = data.get(
            "mode",
            "quick"
        )

        start = data.get("start")
        end = data.get("end")

        ports = build_ports(
            mode,
            start,
            end,
        )

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

        await websocket.send_json(
            {
                "type": "started",
                "target": target,
                "ports": len(ports),
            }
        )

        async def send_event(event):

            await websocket.send_json(event)

        await scanner.run(
            send_event
        )

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

    except WebSocketDisconnect:
        if scanner:
            scanner.stop()

    except Exception as exc:

        try:

            await websocket.send_json(
                {
                    "type": "error",
                    "message": str(exc),
                }
            )

        except Exception:
            pass

    finally:

        if scanner:
            active_scanners.pop(
                id(scanner),
                None,
            )


# ---------------------------------------------------------
# CSV report
# ---------------------------------------------------------

@app.post("/report/csv")
async def csv_report(request: Request):

    data = await request.json()

    results = data.get(
        "results",
        []
    )

    output = io.StringIO()

    writer = csv.writer(output)

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

    for result in results:

        writer.writerow(
            [
                result.get("port"),
                result.get("state"),
                result.get("service"),
                result.get("risk"),
                result.get("latency_ms"),
                result.get("banner"),
            ]
        )

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=psychoport-report.csv"
        },
    )