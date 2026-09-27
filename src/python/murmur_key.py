"""Build-time key provisioning; the ELRS UID is an identifier, never a secret."""
import hashlib
from pathlib import Path


def derive_key(phrase):
    if not phrase:
        raise ValueError("MURMUR_ENCRYPT requires a nonempty build-time binding phrase")
    # Versioned domain separation. Hash the complete UTF-8 phrase, not its UID.
    # This is not password stretching: use a high-entropy, unique phrase.
    return hashlib.sha256(b"MurmurLRS/packet-key/v1\x00" + phrase.encode("utf-8")).digest()[:16]


def write_key_header(build_dir, phrase):
    key = derive_key(phrase)
    path = Path(build_dir) / "murmur_key_generated.h"
    content = ("// Generated locally. Contains a secret; do not publish.\n#pragma once\n"
               "static const uint8_t murmur_build_key[16] = {" +
               ",".join(str(b) for b in key) + "};\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text() != content:
        path.write_text(content)
    return path
