"""Scanner detectors 단위 테스트.

magic_bytes / extension / filename_pattern / parent_dir 4 단 우선순위가
지켜지는지 + 8 개 evidence 타입이 정확히 매칭되는지 검증.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forensicagent.scanner.detectors import (
    detect,
    detect_by_extension,
    detect_by_filename,
    detect_by_magic,
    detect_by_parent_dir,
)


def _write_bytes(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------------------------------------------------------------------------
# magic bytes
# ---------------------------------------------------------------------------

class TestMagicBytes:
    def test_evtx_log(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "Security.evtx", b"ElfFile\x00" + b"\x00" * 50)
        hit = detect_by_magic(p)
        assert hit is not None
        etype, plat, conf = hit
        assert etype == "evtx_log"
        assert plat == "windows"
        assert conf >= 0.95

    def test_pcap_le(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace", b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "pcap"

    def test_pcap_be(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "pcap"

    def test_pcap_nanosecond(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace", b"\x4d\x3c\xb2\xa1" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "pcap"

    def test_pcap_nanosecond_other_endian(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace", b"\xa1\xb2\x3c\x4d" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "pcap"

    def test_pcapng_shb(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "pcap"

    def test_registry_hive(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "NTUSER.DAT", b"regf" + b"\x00" * 50)
        hit = detect_by_magic(p)
        assert hit is not None
        assert hit[0] == "registry_hive"
        assert hit[1] == "windows"

    def test_prefetch_compressed(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "FOO.pf", b"MAM\x04" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "prefetch"

    def test_prefetch_plain(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "FOO.pf", b"SCCA" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "prefetch"

    def test_prefetch_plain_real_header_offset(self, tmp_path: Path) -> None:
        # Plain Prefetch stores its version DWORD first and SCCA at offset 4.
        p = _write_bytes(
            tmp_path,
            "FOO.pf",
            (30).to_bytes(4, "little") + b"SCCA" + b"\x00" * 20,
        )
        hit = detect_by_magic(p)
        assert hit is not None
        assert hit[0] == "prefetch"
        assert hit[2] >= 0.95

    def test_scca_at_offset_four_requires_known_prefetch_version(self, tmp_path: Path) -> None:
        p = _write_bytes(
            tmp_path,
            "not-prefetch.bin",
            (999).to_bytes(4, "little") + b"SCCA" + b"\x00" * 20,
        )
        assert detect_by_magic(p) is None

    def test_disk_image_e01(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "image", b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "disk_image"

    def test_sqlite_browser_artifact(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "History", b"SQLite format 3\x00" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "browser_artifact"

    def test_generic_sqlite_is_not_assumed_browser(self, tmp_path: Path) -> None:
        p = _write_bytes(
            tmp_path,
            "business.sqlite",
            b"SQLite format 3\x00" + b"\x00" * 20,
        )
        assert detect_by_magic(p)[0] == "sqlite_database"

    def test_sqlite_under_browser_parent_is_browser_artifact(self, tmp_path: Path) -> None:
        p = (
            tmp_path
            / "AppData"
            / "Local"
            / "Google"
            / "Chrome"
            / "User Data"
            / "Default"
            / "Favicons"
        )
        p.parent.mkdir(parents=True)
        p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 20)
        assert detect_by_magic(p)[0] == "browser_artifact"

    def test_unknown_bytes_no_match(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "rando", b"random binary data here \x01\x02")
        assert detect_by_magic(p) is None

    def test_empty_file_no_match(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "empty", b"")
        assert detect_by_magic(p) is None

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        p = tmp_path / "does-not-exist"
        assert detect_by_magic(p) is None


# ---------------------------------------------------------------------------
# extension
# ---------------------------------------------------------------------------

class TestExtension:
    @pytest.mark.parametrize(
        "ext,etype",
        [
            (".evtx", "evtx_log"),
            (".pcap", "pcap"),
            (".dmp", "memory_dump"),
            (".lime", "memory_dump"),
            (".e01", "disk_image"),
            (".mft", "ntfs_metadata"),
            (".pf", "prefetch"),
            (".sqlite", "sqlite_database"),
            (".db", "sqlite_database"),
            (".log", "text_log"),
            (".txt", "text_document"),
            (".yaml", "text_document"),
            (".json", "text_document"),
            (".toml", "text_document"),
            (".pem", "text_document"),
            (".sh", "text_document"),
            (".ps1", "text_document"),
            (".bat", "text_document"),
            (".cmd", "text_document"),
            (".xml", "text_document"),
            (".tf", "text_document"),
            (".tfvars", "text_document"),
        ],
    )
    def test_known_extensions(self, tmp_path: Path, ext: str, etype: str) -> None:
        p = tmp_path / f"file{ext}"
        hit = detect_by_extension(p)
        assert hit is not None, f"no match for {ext}"
        assert hit[0] == etype

    def test_unknown_extension(self, tmp_path: Path) -> None:
        assert detect_by_extension(tmp_path / "file.xyz") is None

    def test_legacy_evt_is_not_assumed_to_be_modern_evtx(self, tmp_path: Path) -> None:
        assert detect_by_extension(tmp_path / "Security.evt") is None

    def test_no_extension(self, tmp_path: Path) -> None:
        assert detect_by_extension(tmp_path / "noext") is None

    def test_generic_raw_is_not_assumed_memory(self, tmp_path: Path) -> None:
        assert detect_by_extension(tmp_path / "disk.raw") is None

    def test_browser_sqlite_extension_uses_context(self, tmp_path: Path) -> None:
        hit = detect_by_extension(tmp_path / "Places.sqlite")
        assert hit is not None
        assert hit[0] == "browser_artifact"


# ---------------------------------------------------------------------------
# filename pattern
# ---------------------------------------------------------------------------

class TestFilenamePattern:
    @pytest.mark.parametrize(
        "name,etype",
        [
            ("NTUSER.DAT", "registry_hive"),
            ("UsrClass.dat", "registry_hive"),
            ("SYSTEM", "registry_hive"),
            ("SOFTWARE", "registry_hive"),
            ("SAM", "registry_hive"),
            ("Amcache.hve", "registry_hive"),
            ("memory.raw", "memory_dump"),
            ("memdump.raw", "memory_dump"),
            ("host-physmem.raw", "memory_dump"),
            ("winpmem.raw", "memory_dump"),
            ("memory.bin", "memory_dump"),
            ("$MFT", "ntfs_metadata"),
            ("$J", "ntfs_metadata"),
            ("$Boot", "ntfs_metadata"),
            ("$SDS", "ntfs_metadata"),
            ("$I30", "ntfs_metadata"),
            ("History", "browser_artifact"),
            ("Cookies", "browser_artifact"),
            ("syslog", "text_log"),
            ("auth.log", "text_log"),
            ("secure", "text_log"),
            (".env", "text_document"),
            (".env.local", "text_document"),
            (".npmrc", "text_document"),
            ("Dockerfile", "text_document"),
            ("Makefile", "text_document"),
            ("Jenkinsfile", "text_document"),
        ],
    )
    def test_patterns(self, tmp_path: Path, name: str, etype: str) -> None:
        hit = detect_by_filename(tmp_path / name)
        assert hit is not None, f"no match for {name}"
        assert hit[0] == etype

    def test_unrelated_name(self, tmp_path: Path) -> None:
        assert detect_by_filename(tmp_path / "ReadMe.md") is None


# ---------------------------------------------------------------------------
# parent dir
# ---------------------------------------------------------------------------

class TestParentDir:
    def test_winevt_parent_does_not_override_legacy_evt_format(self) -> None:
        p = Path("C:/Windows/System32/winevt/Logs/Security.evt")
        assert detect_by_parent_dir(p) is None

    def test_prefetch_path_hint(self) -> None:
        p = Path("C:/Windows/Prefetch/CHROME.EXE-XXXX.pf")
        hit = detect_by_parent_dir(p)
        assert hit is not None
        assert hit[0] == "prefetch"

    def test_chrome_browser_path(self) -> None:
        p = Path(
            "C:/Users/foo/AppData/Local/Google/Chrome/User Data/Default/History"
        )
        hit = detect_by_parent_dir(p)
        assert hit is not None
        assert hit[0] == "browser_artifact"

    def test_linux_var_log(self) -> None:
        hit = detect_by_parent_dir(Path("/var/log/auth.log"))
        assert hit is not None
        assert hit[0] == "text_log"
        assert hit[1] == "linux"

    def test_unrelated_path(self) -> None:
        assert detect_by_parent_dir(Path("/tmp/random/file")) is None


# ---------------------------------------------------------------------------
# composite detect() — priority order
# ---------------------------------------------------------------------------

class TestCompositeDetect:
    def test_magic_beats_extension(self, tmp_path: Path) -> None:
        """Wrong extension but correct magic → magic wins."""
        p = _write_bytes(tmp_path, "Security.txt", b"ElfFile\x00" + b"\x00" * 50)
        hit = detect(p)
        assert hit is not None
        assert hit[0] == "evtx_log"
        assert hit[3] == "magic_bytes"

    def test_extension_when_no_magic(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "trace.pcap", b"\x00" * 100)
        hit = detect(p)
        assert hit is not None
        assert hit[3] == "extension"
        assert hit[0] == "pcap"

    def test_filename_when_no_magic_no_ext(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "NTUSER.DAT", b"\x00" * 100)
        # ".DAT" not in extension map, so should fall through to filename.
        hit = detect(p)
        assert hit is not None
        assert hit[3] == "filename_pattern"
        assert hit[0] == "registry_hive"

    def test_unknown(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "thing.xyz", b"\x00\x01\x02")
        assert detect(p) is None

    def test_generic_raw_remains_unknown(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "disk.raw", b"\x00" * 100)
        assert detect(p) is None

    def test_named_raw_memory_dump(self, tmp_path: Path) -> None:
        p = _write_bytes(tmp_path, "memdump.raw", b"\x00" * 100)
        hit = detect(p)
        assert hit is not None
        assert hit[0] == "memory_dump"
        assert hit[3] == "filename_pattern"
