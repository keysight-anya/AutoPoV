"""
Tests for source handler module
"""

import os
import tempfile
import zipfile

import pytest

from app.source_handler import SourceHandler


class TestSourceHandler:
    """Test source code handling"""

    @pytest.fixture
    def handler(self):
        return SourceHandler()

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_handle_raw_code(self, handler):
        code = "def test(): pass"
        scan_id = "test_scan"

        path = handler.handle_raw_code(code, scan_id, "python", "test.py")

        assert os.path.exists(path)
        assert os.path.exists(os.path.join(path, "test.py"))
        with open(os.path.join(path, "test.py"), 'r', encoding='utf-8') as f:
            assert f.read() == code

        handler.cleanup(scan_id)

    def test_handle_zip_upload(self, handler, temp_dir):
        zip_path = os.path.join(temp_dir, "test.zip")
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.py", "def test(): pass")

        scan_id = "test_scan_zip"
        path = handler.handle_zip_upload(zip_path, scan_id)

        assert os.path.exists(path)
        assert os.path.exists(os.path.join(path, "test.py"))

        handler.cleanup(scan_id)

    def test_get_source_info(self, handler, temp_dir):
        os.makedirs(os.path.join(temp_dir, "src"), exist_ok=True)
        with open(os.path.join(temp_dir, "src", "test.py"), 'w', encoding='utf-8') as f:
            f.write("def test():\n    pass\n")

        info = handler.get_source_info(temp_dir)

        assert info["total_files"] == 1
        assert info["total_lines"] == 2
        assert "Python" in info["languages"]

    def test_detect_binary_files(self, handler, temp_dir):
        with open(os.path.join(temp_dir, "test.bin"), 'wb') as f:
            f.write(b"\\x00\\x01\\x02\\x03")

        binaries = handler.detect_binary_files(temp_dir)

        assert len(binaries) == 1
        assert binaries[0].endswith("test.bin")
