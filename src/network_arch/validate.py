from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    rule_id: str
    message: str
    flow_index: int | None = None


def validate_architecture(document: dict[str, object]) -> list[Violation]:
    violations: list[Violation] = []
    zones = document.get("zones", [])
    flows = document.get("flows", [])
    zone_names = {str(zone.get("name")) for zone in zones if isinstance(zone, dict)}

    for required in {"internet", "dmz", "user", "management", "restricted"}:
        if required not in zone_names:
            violations.append(Violation("ARCH-001", f"Required zone is missing: {required}"))

    seen_flows: set[tuple[str, str, str, str]] = set()
    for index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            violations.append(Violation("ARCH-002", "Flow must be an object", index))
            continue
        source = str(flow.get("source", ""))
        destination = str(flow.get("destination", ""))
        protocol = str(flow.get("protocol", "")).lower()
        port = str(flow.get("port", "")).lower()
        action = str(flow.get("action", "deny")).lower()
        key = (source, destination, protocol, port)

        if source not in zone_names or destination not in zone_names:
            violations.append(Violation("ARCH-003", "Flow references an unknown zone", index))
        if action not in {"allow", "deny"}:
            violations.append(Violation("ARCH-004", "Action must be allow or deny", index))
        if action == "allow" and (protocol == "any" or port == "any"):
            violations.append(Violation("ARCH-005", "Allowed flow cannot use any protocol/port", index))
        if source == "internet" and destination == "restricted" and action == "allow":
            violations.append(
                Violation("ARCH-006", "Direct internet access to restricted zone is forbidden", index)
            )
        if destination == "management" and source != "management" and action == "allow":
            if not bool(flow.get("mfa")) or not bool(flow.get("logged")):
                violations.append(
                    Violation(
                        "ARCH-007",
                        "Management access requires MFA and session logging",
                        index,
                    )
                )
        if key in seen_flows:
            violations.append(Violation("ARCH-008", "Duplicate flow definition", index))
        seen_flows.add(key)

    return violations
