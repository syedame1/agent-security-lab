import json
import shutil
import tempfile
import threading
import unittest
import requests
from fake_artifactory.service import (
    create_server,
    is_valid_package_name,
)


class TestPackageNameValidation(unittest.TestCase):
    def test_valid_names(self):
        self.assertTrue(is_valid_package_name("my-package"))
        self.assertTrue(is_valid_package_name("package_123"))
        self.assertTrue(is_valid_package_name("banking-helper-v1"))
        self.assertTrue(is_valid_package_name("simple"))

    def test_invalid_and_path_traversal_names(self):
        self.assertFalse(is_valid_package_name(""))
        self.assertFalse(is_valid_package_name("../something"))
        self.assertFalse(is_valid_package_name("../../etc/passwd"))
        self.assertFalse(is_valid_package_name("/root/pkg"))
        self.assertFalse(is_valid_package_name("..\\something"))
        self.assertFalse(is_valid_package_name("pkg name with spaces"))
        self.assertFalse(is_valid_package_name("pkg$special!"))


class TestFakeArtifactoryService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.server = create_server(host="127.0.0.1", port=8899, storage_dir=cls.temp_dir)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = "http://127.0.0.1:8899"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_health_endpoint(self):
        resp = requests.get(f"{self.base_url}/health", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("status"), "ok")

    def test_publish_and_retrieve_package(self):
        # 1. Publish package
        content = "def calculate_loan(): return 42"
        resp = requests.post(
            f"{self.base_url}/packages/loan-calc",
            data=content,
            headers={"Content-Type": "text/plain"},
            timeout=5
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data.get("message"), "Package stored successfully")
        self.assertEqual(data.get("package", {}).get("name"), "loan-calc")
        self.assertEqual(data.get("package", {}).get("content"), content)

        # 2. Retrieve package
        resp = requests.get(f"{self.base_url}/packages/loan-calc", timeout=5)
        self.assertEqual(resp.status_code, 200)
        pkg_data = resp.json()
        self.assertEqual(pkg_data.get("name"), "loan-calc")
        self.assertEqual(pkg_data.get("content"), content)
        self.assertIn("published_at", pkg_data)

    def test_publish_json_content(self):
        payload = json.dumps({"content": "print('hello world')"})
        resp = requests.post(
            f"{self.base_url}/packages/json-pkg",
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(f"{self.base_url}/packages/json-pkg", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("content"), "print('hello world')")

    def test_list_packages(self):
        # Publish two packages
        requests.post(f"{self.base_url}/packages/pkg-alpha", data="code-alpha", timeout=5)
        requests.post(f"{self.base_url}/packages/pkg-beta", data="code-beta", timeout=5)

        resp = requests.get(f"{self.base_url}/packages", timeout=5)
        self.assertEqual(resp.status_code, 200)
        packages = resp.json().get("packages", [])
        self.assertIn("pkg-alpha", packages)
        self.assertIn("pkg-beta", packages)

    def test_missing_package_handling(self):
        resp = requests.get(f"{self.base_url}/packages/nonexistent-package", timeout=5)
        self.assertEqual(resp.status_code, 404)
        self.assertIn("error", resp.json())

    def test_invalid_package_name_rejection(self):
        # Traversal attempt via POST
        resp = requests.post(f"{self.base_url}/packages/..%2F..%2Fbadpath", data="exploit", timeout=5)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

        # Traversal attempt via GET
        resp = requests.get(f"{self.base_url}/packages/..%2F..%2Fbadpath", timeout=5)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())


if __name__ == "__main__":
    unittest.main()
