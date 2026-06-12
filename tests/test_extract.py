from extract.extract import get_excluded_folders


def test_get_excluded_folders():
    max_extracted, num_files = 10, 3
    listing_data = [
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_1.txt"],
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_2.txt"],
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_3.txt"],
    ]
    assert get_excluded_folders(max_extracted, listing_data, num_files) == []

    max_extracted, num_files = 2, 3
    listing_data = [
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_1.txt"],
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_2.txt"],
        ["2026-06-12 17:26:09", ".....", "14", "14", "files/file_3.txt"],
    ]
    assert get_excluded_folders(max_extracted, listing_data, num_files) == []

    max_extracted = 500
    num_files = 3000
    listing_data = [["2026-06-12 17:26:09", ".....", "14", "14", f"files/file_{i}.txt"] for i in range(0, 3000)]
    assert get_excluded_folders(max_extracted, listing_data, num_files) == []
