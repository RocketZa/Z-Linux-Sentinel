
from pathlib import Path

import yaml


DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"


def load_policy(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict:
    with Path(policy_path).open("r", encoding="utf-8") as file:
        policy = yaml.safe_load(file)

    if not isinstance(policy, dict):
        raise ValueError("Policy must contain a YAML mapping.")

    checks = policy.get("checks")

    if not isinstance(checks, dict):
        raise ValueError("Policy must contain a 'checks' mapping.")

    for check_id, config in checks.items():
        if isinstance(config, bool):
            continue

        if not isinstance(config, dict):
            raise ValueError(
                f"Policy configuration for {check_id} must be a boolean or mapping."
            )

        if check_id == "USR-02":
            admin_groups = config.get("admin_groups")
            allowed_members = config.get("allowed_members")

            if not isinstance(admin_groups, list) or not all(
                isinstance(group, str) for group in admin_groups
            ):
                raise ValueError(
                    "USR-02 admin_groups must be a list of strings."
                )

            if not isinstance(allowed_members, list) or not all(
                isinstance(user, str) for user in allowed_members
            ):
                raise ValueError(
                    "USR-02 allowed_members must be a list of strings."
                )

    return policy
