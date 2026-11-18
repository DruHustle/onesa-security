"""Explicit offline owner bootstrap. Never expose as an HTTP endpoint."""
import argparse
from sqlalchemy import select
from .config import Settings
from .database import db_factory, tenant_context
from .models import Membership, Organization
from .auth import TENANT_RE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--org-name", required=True)
    parser.add_argument("--owner-sub", required=True)
    args = parser.parse_args()
    if not TENANT_RE.fullmatch(args.org_id) or not args.owner_sub or len(args.owner_sub) > 255:
        parser.error("Invalid tenant UUID or owner subject")
    cfg = Settings.from_env()
    _, make_session = db_factory(cfg.database_url)
    with make_session.begin() as session:
        tenant_context(session, args.org_id)
        if session.get(Organization, args.org_id):
            raise RuntimeError("Organization already exists. No destructive bootstrap overwrite")
        session.add(Organization(id=args.org_id, name=args.org_name))
        session.add(Membership(tenant_id=args.org_id, subject=args.owner_sub, role="owner"))
    print("Created organization and owner membership (no credentials emitted)")


if __name__ == "__main__":
    main()
