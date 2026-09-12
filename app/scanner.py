import asyncio
import socket
import time
from typing import Callable, Awaitable, Optional

from .services import get_service, get_risk


EventCallback = Callable[[dict], Awaitable[None]]


class PortScanner:
    def __init__(
        self,
        target: str,
        ports: list[int],
        timeout: float = 0.8,
        workers: int = 100,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = workers

        self.stop_event = asyncio.Event()
        self.results = []

    def stop(self):
        self.stop_event.set()

    async def resolve_target(self):
        loop = asyncio.get_running_loop()

        try:
            ip = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname(self.target),
            )

            return ip

        except socket.gaierror:
            raise ValueError("Unable to resolve target.")

    async def check_port(self, ip: str, port: int):
        if self.stop_event.is_set():
            return None

        start = time.perf_counter()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )

            elapsed = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            banner = await self.grab_banner(
                reader,
                writer,
                port,
            )

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

            service = get_service(port)
            risk = get_risk(port, service)

            return {
                "port": port,
                "state": "OPEN",
                "service": service,
                "risk": risk,
                "latency_ms": elapsed,
                "banner": banner,
            }

        except asyncio.TimeoutError:

            return {
                "port": port,
                "state": "FILTERED",
                "service": get_service(port),
                "risk": "UNKNOWN",
                "latency_ms": None,
                "banner": "",
            }

        except (ConnectionRefusedError, OSError):

            return {
                "port": port,
                "state": "CLOSED",
                "service": get_service(port),
                "risk": "NONE",
                "latency_ms": None,
                "banner": "",
            }

        except Exception:

            return {
                "port": port,
                "state": "UNKNOWN",
                "service": get_service(port),
                "risk": "UNKNOWN",
                "latency_ms": None,
                "banner": "",
            }

    async def grab_banner(
        self,
        reader,
        writer,
        port: int,
    ) -> str:

        try:

            # HTTP service probe
            if port in {
                80,
                3000,
                5000,
                8000,
                8080,
            }:

                request = (
                    "GET / HTTP/1.0\r\n"
                    f"Host: {self.target}\r\n"
                    "Connection: close\r\n\r\n"
                )

                writer.write(request.encode())
                await writer.drain()

            data = await asyncio.wait_for(
                reader.read(512),
                timeout=0.5,
            )

            if not data:
                return ""

            text = data.decode(
                errors="replace"
            ).replace("\r", " ").replace("\n", " ")

            return text[:200]

        except Exception:
            return ""

    async def run(self, callback: EventCallback):

        ip = await self.resolve_target()

        await callback(
            {
                "type": "resolved",
                "target": self.target,
                "ip": ip,
                "total": len(self.ports),
            }
        )

        semaphore = asyncio.Semaphore(self.workers)

        completed = 0
        total = len(self.ports)

        async def worker(port):

            nonlocal completed

            async with semaphore:

                if self.stop_event.is_set():
                    return

                result = await self.check_port(
                    ip,
                    port
                )

                completed += 1

                if result:

                    self.results.append(result)

                    await callback(
                        {
                            "type": "port",
                            "result": result,
                            "completed": completed,
                            "total": total,
                            "progress": round(
                                completed / total * 100,
                                2,
                            ),
                        }
                    )

        tasks = [
            asyncio.create_task(worker(port))
            for port in self.ports
        ]

        await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        open_ports = [
            result
            for result in self.results
            if result["state"] == "OPEN"
        ]

        await callback(
            {
                "type": "complete",
                "total": total,
                "open_ports": len(open_ports),
                "results": self.results,
                "stopped": self.stop_event.is_set(),
            }
        )