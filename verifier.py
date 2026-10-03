#!/usr/bin/env python3
"""Independent verifier for Auditable Group Draw audit JSON files.

Uses only the Python standard library and reimplements the enumeration,
canonicalization and SHA-256 selection procedure independently of the browser app.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

KNOWN_ALGORITHM = "enumerate-valid-assignments-sha256-seed-v1"
TWO_256 = 1 << 256


class VerificationError(ValueError):
    pass


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bit(mask: int, i: int) -> int:
    return (mask >> i) & 1


def validate_config_shape(config: dict[str, Any]) -> None:
    required = {"schemaVersion", "algorithm", "names", "turnNames", "capacities", "fixed", "together", "apart"}
    missing = required - set(config)
    if missing:
        raise VerificationError(f"config is missing fields: {', '.join(sorted(missing))}")

    names = config["names"]
    if not isinstance(names, list) or len(names) < 2 or not all(isinstance(x, str) and x for x in names):
        raise VerificationError("config.names is invalid")
    n = len(names)

    if config["algorithm"] != KNOWN_ALGORITHM:
        raise VerificationError(f"unsupported algorithm: {config['algorithm']!r}")
    if not isinstance(config["turnNames"], list) or len(config["turnNames"]) != 2:
        raise VerificationError("config.turnNames must contain exactly two names")
    if not isinstance(config["capacities"], list) or len(config["capacities"]) != 2:
        raise VerificationError("config.capacities must contain exactly two integers")
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in config["capacities"]):
        raise VerificationError("config.capacities contains an invalid value")
    if not isinstance(config["fixed"], list) or len(config["fixed"]) != n:
        raise VerificationError("config.fixed has the wrong length")
    if any(x not in (None, "T1", "T2") for x in config["fixed"]):
        raise VerificationError("config.fixed contains an invalid value")

    for field, groups in (("together", config["together"]), ("apart", config["apart"])):
        if not isinstance(groups, list):
            raise VerificationError(f"config.{field} must be a list")
        for group in groups:
            if not isinstance(group, list) or len(group) < 2:
                raise VerificationError(f"config.{field} contains an invalid group")
            if any(not isinstance(i, int) or isinstance(i, bool) or not 0 <= i < n for i in group):
                raise VerificationError(f"config.{field} contains an out-of-range participant index")
            if group != sorted(set(group)):
                raise VerificationError(f"config.{field} contains a non-canonical group")
    if any(len(group) != 2 for group in config["apart"]):
        raise VerificationError("config.apart groups must contain exactly two participants for a two-turn draw")


def valid_mask(mask: int, config: dict[str, Any]) -> bool:
    n = len(config["names"])
    size1 = mask.bit_count()
    size2 = n - size1
    if size1 > config["capacities"][0] or size2 > config["capacities"][1]:
        return False

    for i, fixed in enumerate(config["fixed"]):
        if fixed == "T1" and bit(mask, i) != 1:
            return False
        if fixed == "T2" and bit(mask, i) != 0:
            return False

    for group in config["together"]:
        b = bit(mask, group[0])
        if any(bit(mask, i) != b for i in group):
            return False

    for first, second in config["apart"]:
        if bit(mask, first) == bit(mask, second):
            return False

    return True


def enumerate_valid(config: dict[str, Any]) -> list[int]:
    return [mask for mask in range(1 << len(config["names"])) if valid_mask(mask, config)]


def assignment_from_mask(mask: int, names: list[str]) -> list[list[str]]:
    t1: list[str] = []
    t2: list[str] = []
    for i, name in enumerate(names):
        (t1 if bit(mask, i) else t2).append(name)
    return [t1, t2]


def participant_bits(mask: int, names: list[str]) -> list[dict[str, Any]]:
    return [{"position": i, "name": name, "bit": bit(mask, i)} for i, name in enumerate(names)]


def choose_index(config_hash: str, seed: str, valid_count: int) -> dict[str, Any]:
    if valid_count <= 0:
        raise VerificationError("valid assignment count must be positive")
    limit = (TWO_256 // valid_count) * valid_count
    counter = 0
    while True:
        material = f"{config_hash}|{seed}|{counter}"
        digest = sha256_hex(material)
        value = int(digest, 16)
        if value < limit:
            return {
                "index": value % valid_count,
                "counter": counter,
                "digest": digest,
                "material": material,
                "rejectionLimitHex": "0x" + format(limit, "x"),
            }
        counter += 1


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise VerificationError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def verify_audit(audit: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(audit, dict):
        raise VerificationError("audit root must be a JSON object")

    config = audit.get("config")
    if not isinstance(config, dict):
        raise VerificationError("audit.config must be a JSON object")
    validate_config_shape(config)

    normalized = canonical_json(config)
    require_equal(audit.get("normalizedConfig"), normalized, "normalizedConfig")

    config_hash = sha256_hex(normalized)
    require_equal(audit.get("configHash"), config_hash, "configHash")
    require_equal(audit.get("method"), config["algorithm"], "method")

    valid = enumerate_valid(config)
    if not valid:
        raise VerificationError("configuration has no valid assignments")
    require_equal(audit.get("validCount"), len(valid), "validCount")

    seed = audit.get("seed")
    if not isinstance(seed, str) or not seed:
        raise VerificationError("audit.seed must be a non-empty string")
    choice = choose_index(config_hash, seed, len(valid))
    require_equal(audit.get("counter"), choice["counter"], "counter")
    require_equal(audit.get("hashMaterial"), choice["material"], "hashMaterial")
    require_equal(audit.get("selectionDigest"), choice["digest"], "selectionDigest")
    require_equal(audit.get("rejectionLimitHex"), choice["rejectionLimitHex"], "rejectionLimitHex")
    require_equal(audit.get("selectedIndex0"), choice["index"], "selectedIndex0")
    require_equal(audit.get("selectedIndex1"), choice["index"] + 1, "selectedIndex1")

    selected_mask = valid[choice["index"]]
    n = len(config["names"])
    require_equal(audit.get("selectedMaskInteger"), selected_mask, "selectedMaskInteger")
    require_equal(audit.get("selectedMaskBinary"), format(selected_mask, f"0{n}b"), "selectedMaskBinary")
    require_equal(audit.get("participantBits"), participant_bits(selected_mask, config["names"]), "participantBits")
    require_equal(audit.get("assignment"), assignment_from_mask(selected_mask, config["names"]), "assignment")

    return {
        "configHash": config_hash,
        "validCount": len(valid),
        "selectedIndex0": choice["index"],
        "selectedMaskInteger": selected_mask,
        "selectionDigest": choice["digest"],
    }


def verify_file(path: Path) -> dict[str, Any]:
    try:
        audit = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read valid JSON from {path}: {exc}") from exc
    return verify_audit(audit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Auditable Group Draw JSON audit files independently.")
    parser.add_argument("audit", nargs="+", type=Path, help="audit JSON file to verify")
    args = parser.parse_args(argv)

    failed = False
    for path in args.audit:
        try:
            details = verify_file(path)
        except VerificationError as exc:
            failed = True
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            continue
        print(f"PASS {path}")
        print(f"  config hash:       {details['configHash']}")
        print(f"  valid assignments: {details['validCount']}")
        print(f"  selected index:    {details['selectedIndex0']} (base 0)")
        print(f"  selected mask:     {details['selectedMaskInteger']}")
        print(f"  selection digest:  {details['selectionDigest']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
