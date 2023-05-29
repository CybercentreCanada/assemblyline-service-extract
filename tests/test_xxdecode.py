import tempfile

import extract.ext.xxuudecode
import pytest


@pytest.mark.parametrize(
    "body_content, result",
    [
        ("begin 644 testfile\n-AE++\nend", "1"),
        ("begin 644 testfile\n0AH2+\nend", "11"),
        ("begin 644 testfile\n1AH2l\nend", "111"),
        ("begin 644 testfile\n2AH2lAE++\nend", "1111"),
        ("begin 644 testfile\n3AH2lAH2+\nend", "11111"),
        ("begin 644 testfile\n4AH2lAH2l\nend", "111111"),
        ("begin 644 testfile\n5AH2lAH2lAE++\nend", "1111111"),
        ("begin 644 testfile\n6AH2lAH2lAH2+\nend", "11111111"),
        ("begin 644 testfile\n7AH2lAH2lAH2l\nend", "111111111"),
        (
            "begin 644 testfile\ngAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2+\nend",
            "11111111111111111111111111111111111111111111",
        ),
        (
            "begin 644 testfile\nhAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2l\nend",
            "111111111111111111111111111111111111111111111",
        ),
        (
            "begin 644 testfile\nhAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2lAH2l\n-AE++\nend",
            "1111111111111111111111111111111111111111111111",
        ),
        ("\n\nbegin 644 testfile\n-AE++\nend", "1"),
        ("XXEncode  0.0 (PowerArchiver 2009: www.powerarchiver.com)\n\nbegin 644 testfile\n-AE++\nend", "1"),
    ],
)
def test_xxcode_from_file(body_content, result):
    with tempfile.NamedTemporaryFile() as f:
        f.write(body_content.encode())
        f.flush()
        files = extract.ext.xxuudecode.decode_from_file(f.name, extract.ext.xxuudecode.xx_character)
        assert len(files) == 1
        assert files[0][0] == "testfile"
        assert files[0][1] == [ord(x) for x in result]


def test_xxcode_2_files_from_file():
    body_content = "begin 644 testfile\n-AE++\nend\nbegin 644 testfile2\n0AH2+\nend"
    with tempfile.NamedTemporaryFile() as f:
        f.write(body_content.encode())
        f.flush()
        files = extract.ext.xxuudecode.decode_from_file(f.name, extract.ext.xxuudecode.xx_character)
        assert len(files) == 2
        assert files[0][0] == "testfile"
        assert files[0][1] == [ord(x) for x in "1"]
        assert files[1][0] == "testfile2"
        assert files[1][1] == [ord(x) for x in "11"]
