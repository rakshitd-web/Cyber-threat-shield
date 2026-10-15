
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time

from playwright.sync_api import sync_playwright

from services.hardware_report import generate_hardware_report
from services.hardware_scanner import run_hardware_scan


HOST = "127.0.0.1"
PORT = 8765

AGENT_NAME = "CyberThreat Shield Hardware Agent"
AGENT_VERSION = "1.2.0"

ALLOWED_ORIGINS = {
    "http://127.0.0.1:8000",
    "https://cyber-threat-shield.onrender.com"
}

scan_lock = threading.Lock()

scan_running = False
last_scan = None
last_scan_time = None
last_report_html = None
last_report_pdf = None


def get_allowed_origin(handler):
    origin = handler.headers.get("Origin")

    if origin in ALLOWED_ORIGINS:
        return origin

    return None


def add_cors_headers(handler):
    origin = get_allowed_origin(handler)

    if origin:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")

    handler.send_header(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
    )
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type"
    )
    handler.send_header(
        "Access-Control-Allow-Private-Network",
        "true"
    )


def send_json(handler, status_code, data):
    response = json.dumps(
        data,
        default=str
    ).encode("utf-8")

    handler.send_response(status_code)
    handler.send_header(
        "Content-Type",
        "application/json; charset=utf-8"
    )
    handler.send_header(
        "Content-Length",
        str(len(response))
    )
    handler.send_header("Cache-Control", "no-store")

    add_cors_headers(handler)

    handler.end_headers()
    handler.wfile.write(response)


def send_pdf_attachment(handler, pdf_content):
    handler.send_response(200)

    handler.send_header(
        "Content-Type",
        "application/pdf"
    )
    handler.send_header(
        "Content-Length",
        str(len(pdf_content))
    )
    handler.send_header(
        "Content-Disposition",
        'attachment; filename="cyberthreat_hardware_report.pdf"'
    )
    handler.send_header("Cache-Control", "no-store")

    add_cors_headers(handler)

    handler.end_headers()
    handler.wfile.write(pdf_content)


def generate_pdf_report(html_content):
    """
    Convert the generated HTML report to PDF using Chromium.
    The existing HTML report supplies the report's styling.
    """
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        try:
            page = browser.new_page(
                viewport={
                    "width": 1100,
                    "height": 900
                },
                device_scale_factor=1
            )

            # Render using screen styles before producing the PDF.
            page.emulate_media(media="screen")

            page.set_content(
                html_content,
                wait_until="load"
            )

            # Wait for any fonts to finish loading.
            page.evaluate("document.fonts.ready")

            pdf_content = page.pdf(
                format="A4",
                print_background=True,
                prefer_css_page_size=True,
                display_header_footer=False,
                margin={
                    "top": "12mm",
                    "bottom": "12mm",
                    "left": "10mm",
                    "right": "10mm"
                }
            )

            return pdf_content

        finally:
            browser.close()


class HardwareAgentHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):
        self.send_response(204)
        add_cors_headers(self)
        self.end_headers()

    def do_GET(self):
        if self.path == "/report":
            if last_report_pdf is None:
                send_json(
                    self,
                    404,
                    {
                        "success": False,
                        "error": (
                            "No PDF report is available. "
                            "Run a hardware scan first."
                        )
                    }
                )
                return

            send_pdf_attachment(self, last_report_pdf)
            return

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
        global last_report_html
        global last_report_pdf

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
            scan_timestamp = time.time()

            # Generate the styled HTML report.
            report_html = generate_hardware_report(
                hardware,
                scan_timestamp=scan_timestamp,
                agent_version=AGENT_VERSION
            )

            # Convert HTML to PDF.
            report_pdf = generate_pdf_report(report_html)

            # Save the scan and reports only after generation succeeds.
            last_scan = hardware
            last_scan_time = scan_timestamp
            last_report_html = report_html
            last_report_pdf = report_pdf

            send_json(
                self,
                200,
                {
                    "success": True,
                    "agent": AGENT_NAME,
                    "version": AGENT_VERSION,
                    "scan_time": last_scan_time,
                    "hardware": hardware,
                    "report_available": True,
                    "report_format": "pdf"
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

    print(f"{AGENT_NAME} v{AGENT_VERSION}")
    print(f"Listening on http://{HOST}:{PORT}")
    print("Hardware scanner agent is running...")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("Stopping hardware agent...")
        server.shutdown()

    finally:
        server.server_close()


if __name__ == "__main__":
    start_agent()
