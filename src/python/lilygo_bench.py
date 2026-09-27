"""Attach the checked-in T3-S3 bench profile without changing downloaded targets."""
import hashlib
import json
import os

import UnifiedConfiguration

Import("env")

phrase = os.environ.get("MURMUR_BINDING_PHRASE", "")
if not phrase:
    raise ValueError("Set MURMUR_BINDING_PHRASE to the same nonempty value for both bench boards")

role = "TX" if "_TX_" in env["PIOENV"] else "RX"
if role == "TX" and os.environ.get("MURMUR_BENCH_FREERUN") == "1":
    env.Append(CPPDEFINES=["DEBUG_TX_FREERUN"])
    print("Murmur bench: TX free-run enabled; no handset required, bench use only")


def append_bench_profile(source, target, env):
    options = dict(env["OPTIONS_JSON"])
    # Match the existing ELRS binding-phrase encoding, without printing the phrase.
    binding_define = '-DMY_BINDING_PHRASE="' + phrase + '"'
    options["uid"] = list(hashlib.md5(binding_define.encode()).digest()[:6])
    options["wifi-on-interval"] = -1
    profile = os.path.join(env["PROJECT_DIR"], "board_profiles", "lilygo_t3s3_lr1121.json")
    with open(str(target[0]), "r+b") as firmware:
        UnifiedConfiguration.appendToFirmware(
            firmware, "Murmur T3-S3 LR1121 Bench " + role,
            "Murmur T3S3 " + role, json.dumps(options), {}, profile, None)
    print("Murmur bench: attached T3-S3 LR1121 " + role + " profile (2.4 GHz, 10 mW)")


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", append_bench_profile)
