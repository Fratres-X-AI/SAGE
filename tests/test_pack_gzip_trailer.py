"""A pack's gzip CRC32 and length trailer are checked; damage reads as an integrity failure."""

from __future__ import annotations

from pathlib import Path

import pytest

from sage.errors import ChainIntegrityError, SignatureMismatchError
from sage.verify import verify_artifact

VECTORS = Path(__file__).resolve().parent / "vectors"
PACK = VECTORS / "pack" / "valid.sage.tar.gz"
KEY = (VECTORS / "keys" / "hmac.key").read_text(encoding="utf-8").strip()
PIN = (VECTORS / "keys" / "ed25519.public.txt").read_text(encoding="utf-8").strip()


def _verify(path: Path) -> dict:
    return verify_artifact(path, hmac_key=KEY, public_key=PIN, require_signature=True)


def _flipped(tmp_path: Path, offset: int) -> Path:
    data = bytearray(PACK.read_bytes())
    data[offset] ^= 0x01
    out = tmp_path / "flipped.sage.tar.gz"
    out.write_bytes(bytes(data))
    return out


@pytest.mark.parametrize("from_end", [8, 5, 4, 1], ids=["crc32-first", "crc32-last", "isize-first", "isize-last"])
def test_trailer_byte_flip_is_rejected(tmp_path: Path, from_end: int) -> None:
    size = PACK.stat().st_size
    with pytest.raises(ChainIntegrityError) as caught:
        _verify(_flipped(tmp_path, size - from_end))
    assert not isinstance(caught.value, SignatureMismatchError)


def test_damaged_middle_reads_as_integrity_failure_not_signature(tmp_path: Path) -> None:
    with pytest.raises(ChainIntegrityError) as caught:
        _verify(_flipped(tmp_path, PACK.stat().st_size // 2))
    assert not isinstance(caught.value, SignatureMismatchError)


def test_gzip_header_mtime_is_not_bound(tmp_path: Path) -> None:
    assert _verify(_flipped(tmp_path, 5))["ok"]
