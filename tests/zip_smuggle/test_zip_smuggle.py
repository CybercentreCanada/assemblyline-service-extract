import os
import struct
import tempfile
import zipfile

import pytest

from extract.ext.zip_smuggle import detect_zip_smuggling, extract_smuggled_data

EOCD_SIG = b"\x50\x4b\x05\x06"


def _inject_smuggled_data(zip_path: str, payload: bytes, output_path: str):
    """Helper: inject payload between local file entries and central directory."""
    with open(zip_path, "rb") as f:
        data = f.read()

    eocd_off = data.rfind(EOCD_SIG)
    assert eocd_off >= 0, "EOCD not found in source zip"
    eocd = data[eocd_off : eocd_off + 22]
    old_cd = struct.unpack("<I", eocd[16:20])[0]
    new_cd = old_cd + len(payload)
    updated_eocd = eocd[:16] + struct.pack("<I", new_cd) + eocd[20:]
    new_data = data[:old_cd] + payload + data[old_cd:eocd_off] + updated_eocd

    with open(output_path, "wb") as f:
        f.write(new_data)


@pytest.fixture
def work_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


# ── Detection tests ──────────────────────────────────────────────────────────


class TestDetection:
    def test_normal_zip_no_detection(self, work_dir):
        path = os.path.join(work_dir, "normal.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("hello.txt", "Hello, world!")
        assert detect_zip_smuggling(path) is None

    def test_single_file_smuggled(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("hello.txt", "Hello, world!")

        payload = b"secret data"
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_size"] == len(payload)

    def test_multi_file_zip(self, work_dir):
        src = os.path.join(work_dir, "multi.zip")
        smuggled = os.path.join(work_dir, "multi_smuggled.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("file1.txt", "Content of file 1")
            zf.writestr("dir/file2.txt", "Content of file 2")
            zf.writestr("file3.bin", b"\x00\x01\x02\x03" * 100)

        payload = b"multi file payload"
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_size"] == len(payload)

        # Ensure the zip still opens normally
        with zipfile.ZipFile(smuggled, "r") as zf:
            assert sorted(zf.namelist()) == ["dir/file2.txt", "file1.txt", "file3.bin"]

    def test_compressed_zip(self, work_dir):
        src = os.path.join(work_dir, "compressed.zip")
        smuggled = os.path.join(work_dir, "compressed_smuggled.zip")
        with zipfile.ZipFile(src, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "A" * 10000)

        payload = b"compressed test"
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_size"] == len(payload)

    def test_normal_compressed_zip_no_detection(self, work_dir):
        path = os.path.join(work_dir, "compressed.zip")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "A" * 10000)
        assert detect_zip_smuggling(path) is None

    def test_empty_zip_no_detection(self, work_dir):
        path = os.path.join(work_dir, "empty.zip")
        with zipfile.ZipFile(path, "w") as zf:
            pass
        assert detect_zip_smuggling(path) is None

    def test_not_a_zip(self, work_dir):
        path = os.path.join(work_dir, "notazip.bin")
        with open(path, "wb") as f:
            f.write(b"This is not a zip file at all")
        assert detect_zip_smuggling(path) is None

    def test_zero_byte_file(self, work_dir):
        path = os.path.join(work_dir, "empty.bin")
        with open(path, "wb") as f:
            pass
        assert detect_zip_smuggling(path) is None

    def test_large_smuggled_payload(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("readme.txt", "small file")

        payload = os.urandom(100_000)
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_size"] == len(payload)

    def test_smuggled_offset_is_correct(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("a.txt", "aaa")

        # Read the original central directory offset to know where smuggled data starts
        with open(src, "rb") as f:
            original = f.read()
        eocd_off = original.rfind(EOCD_SIG)
        original_cd_off = struct.unpack("<I", original[eocd_off + 16 : eocd_off + 20])[0]

        payload = b"marker"
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_offset"] == original_cd_off

    def test_binary_smuggled_data(self, work_dir):
        """Test with smuggled data containing ZIP-like signatures that could confuse parsing."""
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("test.txt", "test content")

        # Payload contains PK signatures that should not confuse the parser
        payload = b"PK\x03\x04fake_local_header" + b"PK\x01\x02fake_cd"
        _inject_smuggled_data(src, payload, smuggled)

        result = detect_zip_smuggling(smuggled)
        assert result is not None
        assert result["smuggled_size"] == len(payload)


# ── Extraction tests ─────────────────────────────────────────────────────────


class TestExtraction:
    def test_extract_smuggled_data(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        output = os.path.join(work_dir, "extracted.bin")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("hello.txt", "Hello, world!")

        payload = b"This is smuggled secret data!"
        _inject_smuggled_data(src, payload, smuggled)

        result = extract_smuggled_data(smuggled, output)
        assert result == output
        with open(output, "rb") as f:
            assert f.read() == payload

    def test_extract_normal_zip_returns_none(self, work_dir):
        path = os.path.join(work_dir, "normal.zip")
        output = os.path.join(work_dir, "extracted.bin")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("hello.txt", "Hello, world!")

        assert extract_smuggled_data(path, output) is None
        assert not os.path.exists(output)

    def test_extract_not_a_zip_returns_none(self, work_dir):
        path = os.path.join(work_dir, "notazip.bin")
        output = os.path.join(work_dir, "extracted.bin")
        with open(path, "wb") as f:
            f.write(b"not a zip")

        assert extract_smuggled_data(path, output) is None
        assert not os.path.exists(output)

    def test_extract_binary_payload(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        output = os.path.join(work_dir, "extracted.bin")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("a.txt", "aaa")

        payload = bytes(range(256)) * 10
        _inject_smuggled_data(src, payload, smuggled)

        result = extract_smuggled_data(smuggled, output)
        assert result == output
        with open(output, "rb") as f:
            assert f.read() == payload

    def test_extract_large_payload(self, work_dir):
        src = os.path.join(work_dir, "src.zip")
        smuggled = os.path.join(work_dir, "smuggled.zip")
        output = os.path.join(work_dir, "extracted.bin")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("readme.txt", "small file")

        payload = os.urandom(100_000)
        _inject_smuggled_data(src, payload, smuggled)

        result = extract_smuggled_data(smuggled, output)
        assert result == output
        with open(output, "rb") as f:
            assert f.read() == payload

    def test_extract_multi_file_zip(self, work_dir):
        src = os.path.join(work_dir, "multi.zip")
        smuggled = os.path.join(work_dir, "multi_smuggled.zip")
        output = os.path.join(work_dir, "extracted.bin")
        with zipfile.ZipFile(src, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("code.py", "print('hello')\n" * 500)
            zf.writestr("data.bin", os.urandom(5000))
            zf.writestr("nested/deep/file.txt", "deep content")

        payload = b"extracted from multi-file compressed archive"
        _inject_smuggled_data(src, payload, smuggled)

        result = extract_smuggled_data(smuggled, output)
        assert result == output
        with open(output, "rb") as f:
            assert f.read() == payload
