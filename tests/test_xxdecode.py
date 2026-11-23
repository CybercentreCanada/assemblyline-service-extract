import tempfile

import pytest

import extract.ext.xxuudecode


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


@pytest.mark.parametrize(
    "body_content, result",
    [
        ("begin 644 testfile\n!,0``\nend", "1"),
        ("begin 644 testfile\n!,0  \nend", "1"),
        ("begin 644 testfile\n%,3$Q,3$ \nend", "11111"),
    ],
)
def test_uucode_from_file(body_content, result):
    with tempfile.NamedTemporaryFile() as f:
        f.write(body_content.encode())
        f.flush()
        files = extract.ext.xxuudecode.decode_from_file(f.name, extract.ext.xxuudecode.uu_character)
        assert len(files) == 1
        assert files[0][0] == "testfile"
        assert files[0][1] == [ord(x) for x in result]


@pytest.mark.parametrize(
    "character, parse_character",
    [
        ("*", extract.ext.xxuudecode.xx_character),
        ("\x1f", extract.ext.xxuudecode.uu_character),
        ("\x7f", extract.ext.xxuudecode.uu_character),
    ],
)
def test_invalid_character_parsers_raise(character, parse_character):
    with pytest.raises(ValueError):
        parse_character(character)


def test_invalid_character_decodes_as_zero_bits():
    # '*' is not in the XX alphabet; '+' is its zero character, so both decode the same
    corrupted, errors = extract.ext.xxuudecode.decode("AB*CD", extract.ext.xxuudecode.xx_character)
    clean, no_errors = extract.ext.xxuudecode.decode("AB+CD", extract.ext.xxuudecode.xx_character)
    assert corrupted == clean
    assert errors == 1
    assert no_errors == 0


@pytest.mark.parametrize(
    "body_content, result, errors",
    [
        # Corrupted character in the data: rest of the line survives, error reported
        ("begin 644 testfile\n2AH2lA*++\nend", "1110", 1),
        # Junk line between data lines is skipped and reported
        ("begin 644 testfile\n-AE++\nthis is junk that is too long to be a data line\n-AE++\nend", "11", 1),
        # Truncated file with no "end" line still yields the decoded data
        ("begin 644 testfile\n-AE++", "1", 0),
    ],
)
def test_best_effort_decoding(body_content, result, errors):
    with tempfile.NamedTemporaryFile() as f:
        f.write(body_content.encode())
        f.flush()
        files = extract.ext.xxuudecode.decode_from_file(f.name, extract.ext.xxuudecode.xx_character)
        assert len(files) == 1
        assert files[0][0] == "testfile"
        assert files[0][1] == [ord(x) for x in result]
        assert files[0][2] == errors


def test_missing_begin_gets_placeholder_name():
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"-AE++\nend")
        f.flush()
        files = extract.ext.xxuudecode.decode_from_file(f.name, extract.ext.xxuudecode.xx_character)
        assert len(files) == 1
        assert files[0][0] == "decoded_0"
        assert files[0][1] == [ord("1")]


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
