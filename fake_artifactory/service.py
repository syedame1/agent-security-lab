import json
import logging
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

logger = logging.getLogger("fake_artifactory")

VALID_PACKAGE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")


def is_valid_package_name(package_name: str) -> bool:
    """
    Validate that the package name is non-empty, contains only safe alphanumeric,
    dash, and underscore characters, and does not contain path traversal elements.
    """
    if not package_name:
        return False
    if ".." in package_name or "/" in package_name or "\\" in package_name:
        return False
    return bool(VALID_PACKAGE_NAME_PATTERN.fullmatch(package_name))


class FakeArtifactoryRepository:
    def __init__(self, storage_dir: str):
        self.storage_dir = os.path.abspath(storage_dir)
        os.makedirs(self.storage_dir, exist_ok=True)

    def _get_package_path(self, package_name: str) -> str:
        if not is_valid_package_name(package_name):
            raise ValueError(f"Invalid package name: {package_name}")
        package_file = f"{package_name}.json"
        full_path = os.path.abspath(os.path.join(self.storage_dir, package_file))
        # Extra layer of path traversal defense
        if not full_path.startswith(self.storage_dir + os.sep):
            raise ValueError(f"Path traversal detected: {package_name}")
        return full_path

    def publish_package(self, package_name: str, content: str) -> dict:
        full_path = self._get_package_path(package_name)
        data = {
            "name": package_name,
            "content": content,
            "published_at": datetime.now(timezone.utc).isoformat()
        }
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    def get_package(self, package_name: str) -> dict | None:
        full_path = self._get_package_path(package_name)
        if not os.path.exists(full_path):
            return None
        with open(full_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_packages(self) -> list[str]:
        if not os.path.exists(self.storage_dir):
            return []
        packages = []
        for fname in sorted(os.listdir(self.storage_dir)):
            if fname.endswith(".json") and not fname.startswith("."):
                pkg_name = fname[:-5]
                packages.append(pkg_name)
        return packages


class FakeArtifactoryHandler(BaseHTTPRequestHandler):
    repo: FakeArtifactoryRepository = None

    def log_message(self, format, *args):
        # Override default BaseHTTPRequestHandler logging to avoid duplicate/unformatted output
        pass

    def _log_structured(self, action: str, package_name: str | None, success: bool, message: str = ""):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "package_name": package_name if package_name else "N/A",
            "success": success,
            "message": message
        }
        print(f"[FAKE_ARTIFACTORY] {json.dumps(log_entry)}", flush=True)

    def _send_json(self, status_code: int, data: dict):
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        if path == "/health":
            self._log_structured(action="health_check", package_name=None, success=True, message="Health check ok")
            self._send_json(200, {"status": "ok"})
            return

        if path == "/packages":
            pkgs = self.repo.list_packages()
            self._log_structured(action="list_packages", package_name=None, success=True, message=f"Listed {len(pkgs)} packages")
            self._send_json(200, {"packages": pkgs})
            return

        if path.startswith("/packages/"):
            raw_pkg_name = path[len("/packages/"):]
            package_name = urllib.parse.unquote(raw_pkg_name)
            if not is_valid_package_name(package_name):
                self._log_structured(action="get_package", package_name=package_name, success=False, message="Invalid package name")
                self._send_json(400, {"error": "Invalid package name"})
                return

            try:
                pkg_data = self.repo.get_package(package_name)
            except ValueError as e:
                self._log_structured(action="get_package", package_name=package_name, success=False, message=str(e))
                self._send_json(400, {"error": str(e)})
                return

            if pkg_data is None:
                self._log_structured(action="get_package", package_name=package_name, success=False, message="Package not found")
                self._send_json(404, {"error": f"Package '{package_name}' not found"})
                return

            self._log_structured(action="get_package", package_name=package_name, success=True, message="Package retrieved")
            self._send_json(200, pkg_data)
            return

        self._log_structured(action="unknown_route", package_name=None, success=False, message=f"Route not found: {self.path}")
        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/packages/"):
            raw_pkg_name = path[len("/packages/"):]
            package_name = urllib.parse.unquote(raw_pkg_name)
            if not is_valid_package_name(package_name):
                self._log_structured(action="publish_package", package_name=package_name, success=False, message="Invalid package name")
                self._send_json(400, {"error": "Invalid package name"})
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                content_length = 0

            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
            
            # Content could be raw text or json with content field
            content = body
            if body.startswith("{") and body.endswith("}"):
                try:
                    parsed_json = json.loads(body)
                    if isinstance(parsed_json, dict) and "content" in parsed_json:
                        content = str(parsed_json["content"])
                except Exception:
                    pass

            try:
                saved = self.repo.publish_package(package_name, content)
                self._log_structured(action="publish_package", package_name=package_name, success=True, message="Package published successfully")
                self._send_json(201, {
                    "message": "Package stored successfully",
                    "package": saved
                })
            except ValueError as e:
                self._log_structured(action="publish_package", package_name=package_name, success=False, message=str(e))
                self._send_json(400, {"error": str(e)})
            return

        self._log_structured(action="unknown_route", package_name=None, success=False, message=f"Route not found: {self.path}")
        self._send_json(404, {"error": "Not found"})


def create_server(host: str = "127.0.0.1", port: int = 8081, storage_dir: str = None) -> HTTPServer:
    if storage_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        storage_dir = os.path.join(base_dir, "packages")

    repo = FakeArtifactoryRepository(storage_dir)

    class CustomHandler(FakeArtifactoryHandler):
        pass

    CustomHandler.repo = repo
    server = HTTPServer((host, port), CustomHandler)
    return server


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Start Fake Artifactory service")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8081, help="Port to listen on (default: 8081)")
    parser.add_argument("--storage", default=None, help="Storage directory for packages")
    args = parser.parse_args()

    # Enforce listening only on localhost
    if args.host not in ("127.0.0.1", "localhost"):
        print("Warning: Binding to localhost only for security.")
        host = "127.0.0.1"
    else:
        host = args.host

    server = create_server(host=host, port=args.port, storage_dir=args.storage)
    print(f"[FAKE_ARTIFACTORY] Server started on http://{host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[FAKE_ARTIFACTORY] Server stopping...")
        server.server_close()
