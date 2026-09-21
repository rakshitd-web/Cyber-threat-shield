from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time

from services.hardware_scanner import run_hardware_scan


HOST = "127.0.0.1"
PORT = 8765

AGENT_NAME = "CyberThreat Shield Hardware Agent"
AGENT_VERSION = "1.0.0"


ALLOWED_ORIGINS = {
    "http://127.0.0.1:8000",
    "https://cyber-threat-shield.onrender.com"
}


scan_lock = threading.Lock()

scan_running = False
last_scan = None
last_scan_time = None


def get_allowed_origin(handler):

    origin = handler.headers.get("Origin")

    if origin in ALLOWED_ORIGINS:
        return origin

    return None


def send_json(handler, status_code, data):

    response = json.dumps(
        data,
        default=str
    ).encode("utf-8")

    handler.send_response(status_code)

    handler.send_header(
        "Content-Type",
        "application/json"
    )

    handler.send_header(
        "Content-Length",
        str(len(response))
    )

    origin = get_allowed_origin(handler)

    if origin:
        handler.send_header(
            "Access-Control-Allow-Origin",
            origin
        )

    handler.send_header(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
    )

    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type"
    )

    handler.end_headers()

    handler.wfile.write(response)


class HardwareAgentHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):

        self.send_response(204)

        origin = get_allowed_origin(self)

        if origin:
            self.send_header(
                "Access-Control-Allow-Origin",
                origin
            )

        self.send_header(
            "Access-Control-Allow-Methods",
            "GET, POST, OPTIONS"
        )

        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type"
        )

        self.end_headers()

    def do_GET(self):

        if self.path == "/health":

            send_json(
                self,
                200,
                {
                    "success": True,
                    "agent": AGENT_NAME,
                    "version": AGENT_VERSION,
                    "status": "running",
                    "host": HOST,
                    "port": PORT
                }
            )

            return

        send_json(
            self,
            404,
            {
                "success": False,
                "error": "Endpoint not found"
            }
        )

    def do_POST(self):

        global scan_running
        global last_scan
        global last_scan_time

        if self.path != "/scan":

            send_json(
                self,
                404,
                {
                    "success": False,
                    "error": "Endpoint not found"
                }
            )

            return

        if not scan_lock.acquire(blocking=False):

            send_json(
                self,
                409,
                {
                    "success": False,
                    "error": "A hardware scan is already running"
                }
            )

            return

        try:

            scan_running = True

            hardware = run_hardware_scan()

            last_scan = hardware

            last_scan_time = time.time()

            send_json(
                self,
                200,
                {
                    "success": True,
                    "agent": AGENT_NAME,
                    "version": AGENT_VERSION,
                    "scan_time": last_scan_time,
                    "hardware": hardware
                }
            )

        except Exception as e:

            send_json(
                self,
                500,
                {
                    "success": False,
                    "error": str(e)
                }
            )

        finally:

            scan_running = False

            scan_lock.release()


def start_agent():

    server = HTTPServer(
        (HOST, PORT),
        HardwareAgentHandler
    )

    print(
        f"{AGENT_NAME} v{AGENT_VERSION}"
    )

    print(
        f"Listening on http://{HOST}:{PORT}"
    )

    print(
        "Hardware scanner agent is running..."
    )

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("Stopping hardware agent...")

        server.shutdown()


if __name__ == "__main__":

    start_agent()