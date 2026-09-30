"""Provision a separate management credential without exposing compiler flags."""
from pathlib import Path
import re


def write_wifi_header(build_dir, password, binding_phrase):
    if password is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{32}", password):
            raise ValueError("MURMUR_WIFI_PASSWORD must be 32 random hexadecimal characters")
        if password.casefold() == binding_phrase.casefold():
            raise ValueError("Use a separate Wi-Fi credential, not the binding phrase")
    else:
        password = ""
    path = Path(build_dir) / "murmur_wifi_generated.h"
    content = ('// Generated locally. Contains a secret; do not publish.\n#pragma once\n'
               'static const char murmur_wifi_password[] = "' + password + '";\n')
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text() != content:
        path.write_text(content)
    path.chmod(0o600)
    return path
