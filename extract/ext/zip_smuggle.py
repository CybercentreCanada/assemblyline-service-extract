"""Zip smuggling detection and extraction.

Detects data hidden between the end of local file entries and the start of
the central directory in a ZIP archive. This technique, known as "zip smuggling,"
injects payloads that are invisible to standard ZIP tools because they are not
indexed by the central directory.

Normal ZIP structure:
    [Local files...] [Central Directory] [EOCD]

Smuggled ZIP structure:
    [Local files...] [SMUGGLED DATA] [Central Directory] [EOCD]

The EOCD's central directory offset is updated to account for the injected data,
so standard tools work normally while the smuggled data remains hidden.

Reference: https://github.com/Octoberfest7/zip_smuggling
"""

import struct
from typing import Optional

# ZIP signatures
_SIG_LOCAL = b"PK\x03\x04"
_SIG_CENTRAL = b"PK\x01\x02"
_SIG_EOCD = b"PK\x05\x06"
_SIG_DATA_DESC = b"PK\x07\x08"
_SIG_EOCD64_LOC = b"PK\x06\x07"
_SIG_EOCD64 = b"PK\x06\x06"

# Fixed structure sizes
_LFH_FIXED = 30
_CD_FIXED = 46
_EOCD_FIXED = 22
_EOCD64_LOC_FIXED = 20
_EOCD64_MIN = 56


def _find_eocd(data: bytes) -> Optional[int]:
    """Find the End of Central Directory record, searching from end of file.

    Returns:
        The byte offset of the EOCD record, or None if not found.
    """
    start = max(0, len(data) - 0xFFFF - _EOCD_FIXED)
    off = data.rfind(_SIG_EOCD, start)
    return off if off >= 0 else None


def _parse_zip64_extra_field(
    extra: bytes, std_uncompressed: int, std_compressed: int, std_offset: Optional[int] = None
) -> tuple:
    """Parse Zip64 extended information from an extra field block.

    Fields in the Zip64 extra are only present when the corresponding standard
    field is 0xFFFFFFFF. They appear in order: uncompressed_size,
    compressed_size, local_header_offset, disk_start.

    Returns:
        (uncompressed, compressed, offset) with None for absent fields.
    """
    pos = 0
    while pos + 4 <= len(extra):
        hid, dsz = struct.unpack_from("<HH", extra, pos)
        if hid == 0x0001:
            fp = pos + 4
            end = pos + 4 + dsz
            uncompressed = compressed = offset = None
            if std_uncompressed == 0xFFFFFFFF and fp + 8 <= end:
                uncompressed = struct.unpack_from("<Q", extra, fp)[0]
                fp += 8
            if std_compressed == 0xFFFFFFFF and fp + 8 <= end:
                compressed = struct.unpack_from("<Q", extra, fp)[0]
                fp += 8
            if std_offset is not None and std_offset == 0xFFFFFFFF and fp + 8 <= end:
                offset = struct.unpack_from("<Q", extra, fp)[0]
                fp += 8
            return uncompressed, compressed, offset
        pos += 4 + dsz
    return None, None, None


def _get_cd_location(data: bytes) -> Optional[tuple]:
    """Locate the central directory using EOCD (with Zip64 fallback).

    Returns:
        (cd_offset, cd_size, num_entries, ref_offset) where ref_offset is
        the file position used for the prepend/concat calculation.
    """
    eocd_off = _find_eocd(data)
    if eocd_off is None or eocd_off + _EOCD_FIXED > len(data):
        return None

    _, _, _, num_entries, cd_size, cd_offset, _ = struct.unpack_from("<HHHHLLH", data, eocd_off + 4)
    ref_off = eocd_off

    # Check for Zip64 EOCD when standard fields are at their max values
    if cd_offset == 0xFFFFFFFF or num_entries == 0xFFFF or cd_size == 0xFFFFFFFF:
        loc_off = eocd_off - _EOCD64_LOC_FIXED
        if loc_off >= 0 and data[loc_off : loc_off + 4] == _SIG_EOCD64_LOC:
            eocd64_off = data.rfind(_SIG_EOCD64, 0, loc_off)
            if eocd64_off >= 0 and eocd64_off + _EOCD64_MIN <= len(data):
                z64 = struct.unpack_from("<QHHLLQQQQ", data, eocd64_off + 4)
                num_entries = z64[6]
                cd_size = z64[7]
                cd_offset = z64[8]
                ref_off = eocd64_off

    return cd_offset, cd_size, int(num_entries), ref_off


def detect_zip_smuggling(file_path: str) -> Optional[dict]:
    """Detect data smuggled between local file entries and the central directory.

    Parses the ZIP structure to find any gap between where local file data ends
    and where the central directory begins. Any such gap indicates smuggled data.

    Args:
        file_path: Path to the ZIP file to analyze.

    Returns:
        A dict with the following keys if smuggling is detected:
            smuggled_offset: Byte offset where the smuggled data starts.
            smuggled_size: Size of the smuggled data in bytes.
        None if no smuggling is detected or the file is not a valid ZIP.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    loc = _get_cd_location(data)
    if loc is None:
        return None

    cd_offset, cd_size, num_entries, ref_off = loc

    # concat handles ZIP data prepended to another file (e.g. self-extracting archives)
    concat = ref_off - cd_size - cd_offset
    if concat < 0:
        return None

    actual_cd = cd_offset + concat

    # Verify the central directory signature is where we expect it
    if actual_cd + 4 > len(data) or data[actual_cd : actual_cd + 4] != _SIG_CENTRAL:
        return None

    # Walk central directory entries and compute end position of each local file entry
    max_local_end = 0
    cd_pos = actual_cd

    for _ in range(num_entries):
        if cd_pos + _CD_FIXED > len(data) or data[cd_pos : cd_pos + 4] != _SIG_CENTRAL:
            break

        cd_entry = struct.unpack_from("<4s4B4HL2L5H2L", data, cd_pos)
        flags = cd_entry[5]
        std_comp = cd_entry[10]
        std_uncomp = cd_entry[11]
        fn_len = cd_entry[12]
        ex_len = cd_entry[13]
        cm_len = cd_entry[14]
        std_lh_off = cd_entry[18]

        compressed_size = std_comp
        lh_offset = std_lh_off
        uses_zip64 = std_comp == 0xFFFFFFFF or std_uncomp == 0xFFFFFFFF

        # Resolve Zip64 values from the central directory extra field
        if uses_zip64 or std_lh_off == 0xFFFFFFFF:
            extra_data = data[cd_pos + _CD_FIXED + fn_len : cd_pos + _CD_FIXED + fn_len + ex_len]
            _, z64_comp, z64_off = _parse_zip64_extra_field(extra_data, std_uncomp, std_comp, std_lh_off)
            if z64_comp is not None:
                compressed_size = z64_comp
            if z64_off is not None:
                lh_offset = z64_off

        actual_lh = lh_offset + concat

        # Validate local file header signature
        if actual_lh + _LFH_FIXED > len(data) or data[actual_lh : actual_lh + 4] != _SIG_LOCAL:
            cd_pos += _CD_FIXED + fn_len + ex_len + cm_len
            continue

        # Local header may have different filename/extra lengths than the CD entry
        lfh_fn_len, lfh_ex_len = struct.unpack_from("<HH", data, actual_lh + 26)

        entry_end = actual_lh + _LFH_FIXED + lfh_fn_len + lfh_ex_len + compressed_size

        # Account for optional data descriptor (flag bit 3)
        if flags & 0x08:
            # Data descriptor may have an optional PK\x07\x08 signature prefix
            if entry_end + 4 <= len(data) and data[entry_end : entry_end + 4] == _SIG_DATA_DESC:
                entry_end += 4
            # CRC-32 is always 4 bytes; sizes are 4 bytes each (standard) or 8 bytes each (Zip64)
            if uses_zip64:
                entry_end += 20  # CRC(4) + compressed(8) + uncompressed(8)
            else:
                entry_end += 12  # CRC(4) + compressed(4) + uncompressed(4)

        max_local_end = max(max_local_end, entry_end)
        cd_pos += _CD_FIXED + fn_len + ex_len + cm_len

    if max_local_end == 0:
        return None

    gap = actual_cd - max_local_end
    if gap <= 0:
        return None

    return {
        "smuggled_offset": max_local_end,
        "smuggled_size": gap,
    }


def extract_smuggled_data(file_path: str, output_path: str, detection_result: Optional[dict] = None) -> Optional[str]:
    """Extract smuggled data from a ZIP file to the given output path.

    Writes the raw bytes found in the gap between local file entries and the
    central directory to the output path.

    Args:
        file_path: Path to the ZIP file containing smuggled data.
        output_path: Path where the extracted data will be written.
        detection_result: Optional pre-computed result from detect_zip_smuggling.
            If not provided, detect_zip_smuggling will be called.

    Returns:
        output_path on success, None if no smuggled data was found.
    """
    result = detection_result if detection_result is not None else detect_zip_smuggling(file_path)
    if result is None:
        return None

    with open(file_path, "rb") as f:
        f.seek(result["smuggled_offset"])
        smuggled = f.read(result["smuggled_size"])

    if not smuggled:
        return None

    with open(output_path, "wb") as f:
        f.write(smuggled)

    return output_path
