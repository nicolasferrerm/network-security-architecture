from network_arch.validate import validate_architecture


def valid_document():
    return {
        "zones": [
            {"name": name}
            for name in ["internet", "dmz", "user", "management", "restricted"]
        ],
        "flows": [
            {
                "source": "management",
                "destination": "restricted",
                "protocol": "tcp",
                "port": "22",
                "action": "allow",
                "mfa": True,
                "logged": True,
            }
        ],
    }


def test_reference_controls_pass():
    assert validate_architecture(valid_document()) == []


def test_any_any_and_direct_restricted_access_fail():
    document = valid_document()
    document["flows"] = [
        {
            "source": "internet",
            "destination": "restricted",
            "protocol": "any",
            "port": "any",
            "action": "allow",
        }
    ]

    rule_ids = {violation.rule_id for violation in validate_architecture(document)}

    assert rule_ids == {"ARCH-005", "ARCH-006"}


def test_management_access_requires_mfa_and_logging():
    document = valid_document()
    document["flows"] = [
        {
            "source": "user",
            "destination": "management",
            "protocol": "tcp",
            "port": "3389",
            "action": "allow",
        }
    ]

    assert validate_architecture(document)[0].rule_id == "ARCH-007"
