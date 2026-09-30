# Releases and firmware builds

A commit identifies source code. A build compiles that source for a particular board and configuration. Flashing installs the resulting firmware on a device. Pushing a commit does not update installed devices.

`Unreleased` in the changelog groups changes that have not yet been included in a numbered MurmurLRS release. When publishing a release, move those entries under its version and date and start a new `Unreleased` section.

## Release checklist

1. Select a committed revision and verify its GitHub Actions results: encrypted host/crypto/provisioning/packaging checks, sanitizers, encrypted firmware matrix, and the inherited stock checks.
2. Confirm the migration notes and known protocol limitations describe that revision. Do not present compilation as hardware qualification.
3. Assign a MurmurLRS version independently of the upstream ExpressLRS version. Create an annotated version tag at the checked revision and publish release notes summarizing changes, compatibility requirements, and verification scope.
4. Publish source archives and release notes. Do not attach private paired firmware, generated key headers, credentials, internal testing notes, or raw captures.

## Private device builds

Use `tools/build_pair.py` from a clean committed checkout. Both endpoints receive the same private binding phrase and source revision. The command accepts explicit targets and matching hardware profiles, uses a temporary checkout, and writes a private bundle outside the repository. It does not flash devices.

The manifest records the commit, PlatformIO version, regulatory domain, target/profile names, Wi-Fi management provisioning state, firmware/layout checksums, and Lua checksum. Hardware definitions are supplied locally; the copied layouts and hashes record what was used. These records identify build inputs and outputs, but do not promise byte-for-byte reproducibility across toolchain or dependency updates.

Firmware contains compiled secrets. Keep the entire bundle private, including its logs. No binding phrase, packet key, or management password is written into the manifest. Device-specific flashing still requires the correct interface, layout, and recovery procedure.

## CI artifacts

The `Murmur encrypted checks` workflow builds with public fixture credentials and does not publish those encrypted binaries. Its purpose is regression and compilation coverage. The inherited `Build ExpressLRS` workflow uploads stock-path artifacts; those are not substitutes for privately provisioned MurmurLRS pairs.
