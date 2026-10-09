#!/usr/bin/env python3
"""Check each workspace crate without workspace-wide feature unification."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
))
for package in metadata["packages"]:
    variants = [[], ["--no-default-features"]]
    variants += [
        ["--no-default-features", "--features", feature]
        for feature in package["features"]
        if feature != "default"
    ]
    for flags in variants:
        subprocess.run(
            ["cargo", "check", "--locked", "--package", package["name"], *flags],
            check=True,
        )

# Offline consumers must not regain a hidden HTTP/runtime dependency.
for package, flags in [
    ("sigstore-verify", []),
    ("sigstore-verify", ["--no-default-features"]),
    ("sigstore-bundle", []),
    ("sigstore-rekor", ["--no-default-features"]),
    ("sigstore-tsa", ["--no-default-features"]),
]:
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    dependencies = {line.split()[0] for line in tree.splitlines() if line.strip()}
    forbidden = dependencies & {"reqwest", "hyper", "tokio"}
    if forbidden:
        raise SystemExit(f"{package} unexpectedly requires {sorted(forbidden)}")

# Consumers opting out of default features must not regain a hidden aws-lc-rs dependency.
for package, flags in [
    ("sigstore-crypto", ["--no-default-features"]),
    ("sigstore-verify", ["--no-default-features"]),
    ("sigstore-verify", ["--no-default-features", "--features", "tuf,rustls-no-provider"]),
    ("sigstore-sign", ["--no-default-features", "--features", "tuf,rustls-no-provider"]),
    ("sigstore-trust-root", ["--no-default-features"]),
    ("sigstore-tuf", ["--no-default-features", "--features", "rustls-no-provider"]),
    ("sigstore-rekor", ["--no-default-features"]),
    ("sigstore-rekor", ["--no-default-features", "--features", "rustls-no-provider"]),
    ("sigstore-fulcio", ["--no-default-features", "--features", "rustls-no-provider"]),
    ("sigstore-oidc", ["--no-default-features", "--features", "rustls-no-provider"]),
    ("sigstore-tsa", ["--no-default-features"]),
    ("sigstore-tsa", ["--no-default-features", "--features", "rustls-no-provider"]),
]:
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    dependencies = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if "aws-lc-rs" in dependencies:
        raise SystemExit(f"{package} {' '.join(flags)} unexpectedly requires aws-lc-rs")

