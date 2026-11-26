"""Bootstrap the control plane from a shell (uses DATABASE_URL and the other env settings).

    python -m app.control.cli bootstrap --org acme --project support-bot
    python -m app.control.cli create-key --project <project-id> --name ci --scopes guard
    python -m app.control.cli init-db          # create tables (development; use Alembic in production)

The plaintext key is printed once; only its hash is stored.
"""
from __future__ import annotations

import argparse
import json
import sys

from app.control import audit, db, service

ACTOR = "cli"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.control.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create missing tables")

    boot = sub.add_parser("bootstrap", help="create an organization, a project and its first key")
    boot.add_argument("--org", required=True, help="organization slug (created if missing)")
    boot.add_argument("--org-name")
    boot.add_argument("--project", required=True, help="project slug")
    boot.add_argument("--project-name")
    boot.add_argument("--policy", help="initial policy as a JSON string")

    key = sub.add_parser("create-key", help="issue another key for a project")
    key.add_argument("--project", required=True, help="project id")
    key.add_argument("--name", default="default")
    key.add_argument("--scopes", help="comma-separated: chat,guard,models")
    key.add_argument("--expires-in-days", type=int)

    args = parser.parse_args(argv)
    if not db.init_engine(create_tables=args.command == "init-db" or None):
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    if args.command == "init-db":
        print("tables created")
    elif args.command == "bootstrap":
        try:
            org = service.create_org(args.org, args.org_name or args.org, ACTOR)
        except service.Conflict:
            org = service.get_org(args.org)
        policy = json.loads(args.policy) if args.policy else None
        project = service.create_project(org["slug"], args.project, args.project_name or args.project, ACTOR, policy)
        issued = service.create_key(project["id"], ACTOR, name="bootstrap")
        print(json.dumps({"org": org, "project": project, "api_key": issued["key"],
                          "note": "store api_key now; it cannot be shown again"}, indent=2))
    elif args.command == "create-key":
        scopes = [s.strip() for s in args.scopes.split(",")] if args.scopes else None
        issued = service.create_key(args.project, ACTOR, args.name, scopes, args.expires_in_days)
        print(json.dumps(issued, indent=2))
    audit.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
