import argparse
import sys
import sentinel.checks.ssh
import sentinel.checks.users  # Registers USR-01
import sentinel.checks.files
import sentinel.checks.network
from sentinel.runner import run_checks
from sentinel.report import print_terminal, write_json


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Linux Security Auditing and Hardening Toolkit",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run security checks",
    )

    audit_parser.add_argument(
        "--json",
        metavar="PATH",
        help="Save audit results as a JSON file",
    )

    audit_parser.add_argument(
        "--policy",
        metavar="PATH",
        help="Path to a custom YAML policy file",
    )

    args = parser.parse_args()

    if args.command == "audit":
        results = run_checks(policy_path=args.policy)

        print_terminal(results)

        if args.json:
            write_json(results, args.json)
            print(f"JSON report saved to: {args.json}")

        if any(result.status.value == "ERROR" for result in results):
            return 2

        if any(result.status.value == "FAIL" for result in results):
            return 1

        return 0


if __name__ == "__main__":
    sys.exit(main())