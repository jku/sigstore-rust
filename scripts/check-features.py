#!/usr/bin/env python3
"""Check each workspace crate without workspace-wide feature unification."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
))
for package in metadata["packages"]:
    features = package["features"]
    if "aws-lc-rs" in features:
        variants = [
            [],
            ["--no-default-features", "--features", "aws-lc-rs"],
            ["--no-default-features", "--features", "boring"],
        ]
        for feature in features:
            if feature not in {"default", "aws-lc-rs", "boring"}:
                variants.append(
                    ["--no-default-features", "--features", f"aws-lc-rs,{feature}"]
                )
                variants.append(
                    ["--no-default-features", "--features", f"boring,{feature}"]
                )
    else:
        variants = [[], ["--no-default-features"]]
        variants += [
            ["--no-default-features", "--features", feature]
            for feature in features
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
    ("sigstore-verify", ["--no-default-features", "--features", "aws-lc-rs"]),
    ("sigstore-verify", ["--no-default-features", "--features", "boring"]),
    ("sigstore-bundle", []),
    ("sigstore-rekor", ["--no-default-features", "--features", "aws-lc-rs"]),
    ("sigstore-tsa", ["--no-default-features", "--features", "aws-lc-rs"]),
]:
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    dependencies = {line.split()[0] for line in tree.splitlines() if line.strip()}
    forbidden = dependencies & {"reqwest", "hyper", "tokio"}
    if forbidden:
        raise SystemExit(f"{package} unexpectedly requires {sorted(forbidden)}")

# BoringSSL consumers using rustls-no-provider must not pull in aws-lc-rs.
for package, flags in [
    ("sigstore-crypto", ["--no-default-features", "--features", "boring"]),
    ("sigstore-verify", ["--no-default-features", "--features", "boring,rustls-no-provider,tuf"]),
    ("sigstore-sign", ["--no-default-features", "--features", "boring,rustls-no-provider,tuf"]),
]:
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    dependencies = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if "aws-lc-rs" in dependencies:
        raise SystemExit(f"{package} ({flags}) unexpectedly requires aws-lc-rs")
