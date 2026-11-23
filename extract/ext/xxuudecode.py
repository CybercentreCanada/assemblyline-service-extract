xx_consts = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xx_character(c):
    k = xx_consts.find(c)
    if k == -1:
        raise ValueError(f"Invalid XXencode character: {c!r}")
    return k


def uu_character(c):
    if c == "`":
        return 0
    k = ord(c) - 32
    if not 0 <= k < 64:
        raise ValueError(f"Invalid UUencode character: {c!r}")
    return k


# Lines encode at most 45 bytes of data in both XXencode and UUencode
MAX_LINE_DATA = 45


def decode(s, parse_character):
    """Best-effort decode of one line of 6-bit characters into byte values.

    Invalid characters decode as zero bits so a single corrupted character does not
    cost the rest of the line.

    Args:
        s: The data characters of one encoded line, without the leading length character.
        parse_character: Function mapping one character to its 6-bit value, raising
            ValueError on characters outside the alphabet.

    Returns:
        A (data, errors) tuple, where data is the decoded byte values as a list of ints
        and errors is the number of invalid characters that were decoded as zero bits.
    """
    ans = []
    bits = 0
    nbits = 0
    errors = 0
    for c in s:
        try:
            k = parse_character(c)
        except ValueError:
            k = 0
            errors += 1
        bits = (bits << 6) | k
        nbits += 6
        if nbits >= 8:
            nbits -= 8
            ans.append(bits >> nbits)
            bits &= (1 << nbits) - 1
    if nbits:
        # Flush leftover bits as a zero-padded byte: trailing zero-valued characters
        # (spaces in UUencode) may have been stripped from the line
        ans.append((bits << (8 - nbits)) & 0xFF)
    return ans, errors


def decode_from_file(file_path, parse_character):
    """Best-effort decode of an XXencoded or UUencoded file.

    Unparsable lines are skipped, a missing "begin" gets a placeholder file name, and a
    truncated file missing its "end" still yields the data decoded so far.

    Args:
        file_path: Path of the encoded file to decode.
        parse_character: Function mapping one character to its 6-bit value, raising
            ValueError on characters outside the alphabet.

    Returns:
        A list with one (name, data, errors) tuple per file found: the file name from the
        "begin" line, the decoded byte values as a list of ints, and the number of invalid
        characters and skipped lines encountered while decoding that file.
    """
    with open(file_path, "r", errors="replace") as f:
        lines = f.readlines()
    files = []
    ans = []
    errors = 0
    output_file = None
    for line in lines:
        line = line.strip()
        if line == "" or line.startswith("XXEncode  ") or line.startswith("UUEncode  ") or line.endswith(" bytes"):
            continue
        if line.startswith("begin "):
            output_file = line.split(" ", 2)[-1].strip()
            continue
        if line == "end":
            if output_file is not None or ans:
                files.append((output_file or f"decoded_{len(files)}", ans, errors))
            ans = []
            errors = 0
            output_file = None
            continue
        try:
            length = parse_character(line[0])
        except ValueError:
            length = -1
        if length == 0:
            continue
        decoded, line_errors = decode(line[1:], parse_character)
        if not 0 < length <= MAX_LINE_DATA:
            # Invalid or out-of-range length character: recover the line if the rest
            # decodes cleanly as data, otherwise treat it as junk and skip it
            errors += 1
            if line_errors or not decoded:
                continue
            length = min(MAX_LINE_DATA, len(decoded))
        errors += line_errors
        if len(decoded) < length:
            # Trailing zero-valued characters (spaces in UUencode) were stripped; they decode to zero bytes
            decoded.extend([0] * (length - len(decoded)))
        ans.extend(decoded[:length])
    if ans:
        # Truncated file with no "end" line: keep what was decoded
        files.append((output_file or f"decoded_{len(files)}", ans, errors))
    return files


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 3:
        print(f"Usage : {Path(__file__).name} [XXE, UUE] <filename>")
        exit(1)
    # Default to xxdecoding
    parse_character = xx_character
    if sys.argv[1] == "UUE":
        parse_character = uu_character
    file_path = sys.argv[2]
    files = decode_from_file(file_path, parse_character)
    for output_file, ans, errors in files:
        if errors:
            print(f"{output_file}: {errors} invalid character(s)/line(s) ignored, output may be incomplete")
        with open(output_file, "wb") as f:
            f.write(bytes(ans))
