#!/usr/bin/env python3
"""Independent verifier for Auditable Group Draw audit JSON files.

Uses only the Python standard library and reimplements canonicalization,
constraint checking, exhaustive enumeration and SHA-256 selection independently
of the browser application.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

KNOWN_APP = "auditable-group-draw"
KNOWN_ALGORITHM = "enumerate-valid-assignments-sha256-seed-v1"
KNOWN_CONFIG_SCHEMA = "2"
KNOWN_AUDIT_SCHEMA = "2"
MAX_PARTICIPANTS = 20
MAX_NAME_LENGTH = 200
MAX_TURN_NAME_LENGTH = 100
MAX_SEED_LENGTH = 4096
MAX_AUDIT_BYTES = 1_000_000
TWO_256 = 1 << 256
UNSAFE_INVISIBLE = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
FORBIDDEN_NAME_SEPARATORS = re.compile(r"[+,;|]")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
UTC_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class VerificationError(ValueError):
    pass


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bit(mask: int, i: int) -> int:
    return (mask >> i) & 1


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def require_int(value: Any, label: str, minimum: int | None = None, maximum: int | None = None) -> int:
    if not is_int(value):
        raise VerificationError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise VerificationError(f"{label} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise VerificationError(f"{label} must be <= {maximum}")
    return value


def require_exact_keys(obj: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(obj)
    missing = expected - actual
    extra = actual - expected
    problems = []
    if missing:
        problems.append("missing " + ", ".join(sorted(missing)))
    if extra:
        problems.append("unexpected " + ", ".join(sorted(extra)))
    if problems:
        raise VerificationError(f"{label} fields are invalid: {'; '.join(problems)}")


def validate_text(value: Any, label: str, max_length: int, *, forbid_separators: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise VerificationError(f"{label} must not contain leading or trailing whitespace")
    if unicodedata.normalize("NFC", value) != value:
        raise VerificationError(f"{label} must be NFC-normalized")
    if len(value) > max_length:
        raise VerificationError(f"{label} exceeds {max_length} characters")
    if UNSAFE_INVISIBLE.search(value):
        raise VerificationError(f"{label} contains a forbidden control or invisible formatting character")
    if forbid_separators and FORBIDDEN_NAME_SEPARATORS.search(value):
        raise VerificationError(f"{label} contains a reserved constraint separator")
    return value


def validate_group_collection(groups: Any, field: str, n: int, *, pairs_only: bool) -> None:
    if not isinstance(groups, list):
        raise VerificationError(f"config.{field} must be a list")
    canonical: list[list[int]] = []
    for group in groups:
        if not isinstance(group, list) or len(group) < 2:
            raise VerificationError(f"config.{field} contains an invalid group")
        if pairs_only and len(group) != 2:
            raise VerificationError(f"config.{field} groups must contain exactly two participants")
        if any(not is_int(i) or not 0 <= i < n for i in group):
            raise VerificationError(f"config.{field} contains an out-of-range participant index")
        if group != sorted(set(group)):
            raise VerificationError(f"config.{field} contains a non-canonical group")
        canonical.append(group)
    expected = sorted({tuple(group) for group in canonical})
    if [tuple(group) for group in groups] != expected:
        raise VerificationError(f"config.{field} groups are not canonically sorted and deduplicated")


def validate_config_shape(config: dict[str, Any]) -> None:
    required = {"schemaVersion", "algorithm", "names", "turnNames", "capacities", "fixed", "together", "apart"}
    require_exact_keys(config, required, "config")

    if config["schemaVersion"] != KNOWN_CONFIG_SCHEMA:
        raise VerificationError(f"unsupported config schema: {config['schemaVersion']!r}")
    if config["algorithm"] != KNOWN_ALGORITHM:
        raise VerificationError(f"unsupported algorithm: {config['algorithm']!r}")

    names = config["names"]
    if not isinstance(names, list) or not 2 <= len(names) <= MAX_PARTICIPANTS:
        raise VerificationError(f"config.names must contain between 2 and {MAX_PARTICIPANTS} participants")
    normalized_names = [validate_text(x, "participant name", MAX_NAME_LENGTH, forbid_separators=True) for x in names]
    name_keys = [name.lower() for name in normalized_names]
    if len(name_keys) != len(set(name_keys)):
        raise VerificationError("config.names contains duplicate or indistinguishable participant names")
    n = len(names)

    turns = config["turnNames"]
    if not isinstance(turns, list) or len(turns) != 2:
        raise VerificationError("config.turnNames must contain exactly two names")
    turn_names = [validate_text(x, "turn name", MAX_TURN_NAME_LENGTH) for x in turns]
    if turn_names[0].lower() == turn_names[1].lower():
        raise VerificationError("config.turnNames must be distinct")

    capacities = config["capacities"]
    if not isinstance(capacities, list) or len(capacities) != 2:
        raise VerificationError("config.capacities must contain exactly two integers")
    cap1 = require_int(capacities[0], "config.capacities[0]", 0, MAX_PARTICIPANTS)
    cap2 = require_int(capacities[1], "config.capacities[1]", 0, MAX_PARTICIPANTS)
    if n > cap1 + cap2:
        raise VerificationError("config capacities cannot hold every participant")

    fixed = config["fixed"]
    if not isinstance(fixed, list) or len(fixed) != n:
        raise VerificationError("config.fixed has the wrong length")
    if any(x not in (None, "T1", "T2") for x in fixed):
        raise VerificationError("config.fixed contains an invalid value")

    validate_group_collection(config["together"], "together", n, pairs_only=False)
    validate_group_collection(config["apart"], "apart", n, pairs_only=True)


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
    if type(actual) is not type(expected) or actual != expected:
        raise VerificationError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def validate_audit_shape(audit: dict[str, Any]) -> None:
    expected = {
        "auditSchemaVersion", "app", "appVersion", "sourceRepository", "sourceVersion",
        "localDateTime", "utcDateTime", "method", "config", "normalizedConfig", "configHash",
        "seed", "validCount", "selectedIndex0", "selectedIndex1", "selectedMaskInteger",
        "selectedMaskBinary", "participantBits", "counter", "hashMaterial", "selectionDigest",
        "rejectionLimitHex", "assignment"
    }
    require_exact_keys(audit, expected, "audit")
    if audit["auditSchemaVersion"] != KNOWN_AUDIT_SCHEMA:
        raise VerificationError(f"unsupported audit schema: {audit['auditSchemaVersion']!r}")
    if audit["app"] != KNOWN_APP:
        raise VerificationError(f"unexpected app identifier: {audit['app']!r}")
    if not isinstance(audit["appVersion"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", audit["appVersion"]):
        raise VerificationError("audit.appVersion is invalid")
    require_equal(audit["sourceVersion"], "v" + audit["appVersion"], "sourceVersion")
    require_equal(audit["sourceRepository"], "https://github.com/lpla/auditable-group-draw", "sourceRepository")
    for field in ("localDateTime", "utcDateTime", "normalizedConfig", "hashMaterial", "rejectionLimitHex"):
        if not isinstance(audit[field], str) or not audit[field]:
            raise VerificationError(f"audit.{field} must be a non-empty string")
    if not UTC_ISO.fullmatch(audit["utcDateTime"]):
        raise VerificationError("audit.utcDateTime must use the browser ISO UTC timestamp format")
    if not HEX_64.fullmatch(audit["configHash"] if isinstance(audit["configHash"], str) else ""):
        raise VerificationError("audit.configHash is not a lowercase SHA-256 digest")
    if not HEX_64.fullmatch(audit["selectionDigest"] if isinstance(audit["selectionDigest"], str) else ""):
        raise VerificationError("audit.selectionDigest is not a lowercase SHA-256 digest")
    validate_text(audit["seed"], "audit.seed", MAX_SEED_LENGTH)
    for field in ("validCount", "selectedIndex0", "selectedIndex1", "selectedMaskInteger", "counter"):
        require_int(audit[field], f"audit.{field}", 0)
    if not isinstance(audit["participantBits"], list):
        raise VerificationError("audit.participantBits must be a list")
    if not isinstance(audit["assignment"], list) or len(audit["assignment"]) != 2:
        raise VerificationError("audit.assignment must contain exactly two groups")


def verify_audit(audit: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(audit, dict):
        raise VerificationError("audit root must be a JSON object")
    validate_audit_shape(audit)

    config = audit["config"]
    if not isinstance(config, dict):
        raise VerificationError("audit.config must be a JSON object")
    validate_config_shape(config)

    normalized = canonical_json(config)
    require_equal(audit["normalizedConfig"], normalized, "normalizedConfig")

    config_hash = sha256_hex(normalized)
    require_equal(audit["configHash"], config_hash, "configHash")
    require_equal(audit["method"], config["algorithm"], "method")

    valid = enumerate_valid(config)
    if not valid:
        raise VerificationError("configuration has no valid assignments")
    require_equal(audit["validCount"], len(valid), "validCount")

    seed = audit["seed"]
    choice = choose_index(config_hash, seed, len(valid))
    require_equal(audit["counter"], choice["counter"], "counter")
    require_equal(audit["hashMaterial"], choice["material"], "hashMaterial")
    require_equal(audit["selectionDigest"], choice["digest"], "selectionDigest")
    require_equal(audit["rejectionLimitHex"], choice["rejectionLimitHex"], "rejectionLimitHex")
    require_equal(audit["selectedIndex0"], choice["index"], "selectedIndex0")
    require_equal(audit["selectedIndex1"], choice["index"] + 1, "selectedIndex1")

    selected_mask = valid[choice["index"]]
    n = len(config["names"])
    require_equal(audit["selectedMaskInteger"], selected_mask, "selectedMaskInteger")
    require_equal(audit["selectedMaskBinary"], format(selected_mask, f"0{n}b"), "selectedMaskBinary")
    require_equal(audit["participantBits"], participant_bits(selected_mask, config["names"]), "participantBits")
    require_equal(audit["assignment"], assignment_from_mask(selected_mask, config["names"]), "assignment")

    return {
        "configHash": config_hash,
        "validCount": len(valid),
        "selectedIndex0": choice["index"],
        "selectedMaskInteger": selected_mask,
        "selectionDigest": choice["digest"],
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise VerificationError(f"duplicate JSON object key: {key!r}")
        obj[key] = value
    return obj


def verify_file(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VerificationError(f"cannot stat {path}: {exc}") from exc
    if size > MAX_AUDIT_BYTES:
        raise VerificationError(f"audit file is too large: {size} bytes (maximum {MAX_AUDIT_BYTES})")
    try:
        audit = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except VerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
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
