import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from app import create_app


class CaseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(root / "test.sqlite3"),
            "EVIDENCE_DIR": str(root / "evidence"),
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def csrf(self):
        response = self.client.get("/")
        with self.client.session_transaction() as sess:
            return sess["_csrf_token"]

    def create_case(self):
        token = self.csrf()
        response = self.client.post("/cases/new", data={
            "_csrf_token": token,
            "title": "Test forensic case",
            "description": "Unit test case"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        return 1

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Digital Forensics Case Manager", response.data)

    def test_create_case_and_reject_short_title(self):
        token = self.csrf()
        bad = self.client.post("/cases/new", data={"_csrf_token": token, "title": "ab"})
        self.assertEqual(bad.status_code, 200)
        self.assertIn(b"3", bad.data)
        token = self.csrf()
        good = self.client.post("/cases/new", data={"_csrf_token": token, "title": "Test forensic case"})
        self.assertEqual(good.status_code, 302)

    def test_upload_hash_and_download(self):
        self.create_case()
        token = self.csrf()
        content = b"sample event log evidence"
        response = self.client.post("/cases/1/evidence", data={
            "_csrf_token": token,
            "evidence_file": (io.BytesIO(content), "sample.log"),
            "notes": "Test upload"
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 302)
        detail = self.client.get("/cases/1")
        expected = hashlib.sha256(content).hexdigest().encode()
        self.assertIn(expected, detail.data)
        download = self.client.get("/evidence/1/download")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, content)

    def test_reject_disallowed_extension(self):
        self.create_case()
        token = self.csrf()
        response = self.client.post("/cases/1/evidence", data={
            "_csrf_token": token,
            "evidence_file": (io.BytesIO(b"not executable"), "payload.exe")
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unsupported file type", response.data)

    def test_note_and_status_update(self):
        self.create_case()
        token = self.csrf()
        response = self.client.post("/cases/1/notes", data={
            "_csrf_token": token, "body": "Timeline review started."
        })
        self.assertEqual(response.status_code, 302)
        token = self.csrf()
        response = self.client.post("/cases/1/status", data={
            "_csrf_token": token, "status": "In Progress"
        })
        self.assertEqual(response.status_code, 302)
        detail = self.client.get("/cases/1")
        self.assertIn(b"Timeline review started.", detail.data)
        self.assertIn(b"In Progress", detail.data)

    def test_reject_missing_csrf(self):
        response = self.client.post("/cases/new", data={"title": "No token case"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
