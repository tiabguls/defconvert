#!/usr/bin/env python3
"""
defconvert.py — Convert defclone.py JSON output to BloodHound OpenGraph format.

Input:  JSON file produced by defclone.py (dict keyed by Entra device GUID)
Output: BloodHound OpenGraph JSON

Node kinds emitted
  AZDevice  — Entra/Defender device; ID = Entra device GUID
              Merges with existing AZDevice nodes in BloodHound.
  MDE_CVE   — Unique vulnerability; ID = CVE ID string (e.g. CVE-2021-34527)
  AZUser    — Entra user with a known aadUserId; ID = Entra user GUID
              Merges with existing AZUser nodes in BloodHound.
  User      — AD user with a known accountSid but no aadUserId; ID = accountSid.
              Merges with existing AD User nodes in BloodHound by SID.
  MDE_User  — Local/unknown user with no aadUserId and no accountSid;
              ID = DOMAIN\\accountName (synthetic, no existing BH match guaranteed).

Edges emitted
  MDE_CVE   -[FoundOn]->          AZDevice
  AZDevice  -[MDE_LoggedOnTo]->   AZUser | User | MDE_User
"""

import argparse
import json
import sys
from pathlib import Path

from bhopengraph import Edge, Node, OpenGraph, Properties


# ---------------------------------------------------------------------------
# Node builders
# ---------------------------------------------------------------------------

def _set_if(props: Properties, key: str, value) -> None:
    """Set a primitive property, skipping None and unsupported types."""
    if value is None:
        return
    if isinstance(value, (str, int, float, bool)):
        props[key] = value


def _set_str_list(props: Properties, key: str, value) -> None:
    """Set a homogeneous list-of-strings property, skipping empty/None."""
    if not value or not isinstance(value, list):
        return
    coerced = [str(item) for item in value]
    if coerced:
        props[key] = coerced


def make_device_node(entra_id: str, machine: dict) -> Node:
    props = Properties()
    props["entraDeviceId"] = entra_id.upper()
    _set_if(props, "defenderId",      machine.get("id"))
    _set_if(props, "computerDnsName", machine.get("computerDnsName"))
    _set_if(props, "osPlatform",      machine.get("osPlatform"))
    _set_if(props, "osVersion",       machine.get("osVersion"))
    _set_if(props, "healthStatus",    machine.get("healthStatus"))
    _set_if(props, "riskScore",       machine.get("riskScore"))
    _set_if(props, "exposureLevel",   machine.get("exposureLevel"))
    _set_if(props, "firstSeen",       machine.get("firstSeen"))
    _set_if(props, "lastSeen",        machine.get("lastSeen"))
    _set_if(props, "onboardingStatus",machine.get("onboardingStatus"))
    _set_if(props, "isAadJoined",     machine.get("isAadJoined"))
    _set_str_list(props, "machineTags", machine.get("machineTags"))
    return Node(id=entra_id.upper(), kinds=["AZDevice"], properties=props)


def make_cve_node(vuln: dict) -> Node:
    cve_id = vuln["id"]
    props = Properties()
    _set_if(props, "name",           vuln.get("name"))
    _set_if(props, "description",    vuln.get("description"))
    _set_if(props, "severity",       vuln.get("severity"))
    cvss = vuln.get("cvssV3")
    if cvss is not None:
        try:
            props["cvssV3"] = float(cvss)
        except (TypeError, ValueError):
            pass
    _set_if(props, "publicExploit",   vuln.get("publicExploit"))
    _set_if(props, "exploitVerified", vuln.get("exploitVerified"))
    _set_if(props, "exploitInKit",    vuln.get("exploitInKit"))
    _set_if(props, "publishedOn",     vuln.get("publishedOn"))
    _set_if(props, "updatedOn",       vuln.get("updatedOn"))
    _set_str_list(props, "exploitTypes", vuln.get("exploitTypes"))
    return Node(id=cve_id, kinds=["MDE_CVE"], properties=props)


def _resolve_user_id_and_kind(user: dict) -> tuple[str, str]:
    """
    Determine the node ID and kind for a logon user record.

    Priority:
      1. aadUserId  → AZUser (links to existing Entra user in BloodHound)
      2. accountSid → User   (links to existing AD user in BloodHound by SID)
      3. DOMAIN\\name       → User   (synthetic node; no existing BH match guaranteed)
    """
    aad_id = user.get("aadUserId")
    if aad_id:
        return aad_id, "AZUser"

    sid = user.get("accountSid")
    if sid:
        return sid, "User"

    domain = user.get("accountDomain") or "UNKNOWN"
    name   = user.get("accountName")   or "UNKNOWN"
    return f"{domain}\\{name}", "MDE_User"


def make_user_node(user: dict) -> Node:
    node_id, kind = _resolve_user_id_and_kind(user)
    props = Properties()
    _set_if(props, "accountName",   user.get("accountName"))
    _set_if(props, "accountDomain", user.get("accountDomain"))
    _set_if(props, "accountSid",    user.get("accountSid"))
    _set_if(props, "isDomainAdmin", user.get("isDomainAdmin"))
    _set_if(props, "firstSeen",     user.get("firstSeen"))
    _set_if(props, "lastSeen",      user.get("lastSeen"))
    _set_str_list(props, "logonTypes", user.get("logonTypes"))
    return Node(id=node_id, kinds=[kind], properties=props)


def make_loggedon_edge(entra_id: str, user: dict) -> Edge:
    user_id, _ = _resolve_user_id_and_kind(user)
    props = Properties()
    _set_if(props, "firstSeen", user.get("firstSeen"))
    _set_if(props, "lastSeen",  user.get("lastSeen"))
    _set_str_list(props, "logonTypes", user.get("logonTypes"))
    return Edge(
        start_node=entra_id,
        end_node=user_id,
        kind="MDE_LoggedOnTo",
        properties=props if len(props) > 0 else None,
    )


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def convert(data: dict) -> OpenGraph:
    graph = OpenGraph()

    for entra_id, entry in data.items():
        machine = entry.get("machine") or {}
        vulns   = entry.get("vulnerabilities") or []
        users   = entry.get("logonUsers") or []

        # Device node — always add first so edges can reference it
        graph.add_node(make_device_node(entra_id, machine))

        # CVE nodes + FoundOn edges
        for vuln in vulns:
            cve_id = vuln.get("id")
            if not cve_id:
                continue
            graph.add_node(make_cve_node(vuln))       # no-op if already present
            graph.add_edge(Edge(
                start_node=cve_id,
                end_node=entra_id,
                kind="MDE_FoundOn",
            ))

        # User nodes + LoggedOnTo edges
        for user in users:
            user_node = make_user_node(user)
            graph.add_node(user_node)                  # no-op if already present
            graph.add_edge(make_loggedon_edge(entra_id, user))

    return graph


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert defclone.py JSON output to BloodHound OpenGraph format."
    )
    parser.add_argument("input", help="Path to defclone JSON file")
    parser.add_argument(
        "-o", "--output",
        help="Write OpenGraph JSON to this file (default: stdout)",
    )
    parser.add_argument(
        "--indent", type=int, default=2,
        help="JSON indent level (default: 2; use 0 for compact output)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(input_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {input_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print("error: expected a JSON object at the top level", file=sys.stderr)
        sys.exit(1)

    graph = convert(data)

    # Summary to stderr so it doesn't pollute stdout-piped output
    total_nodes = graph.get_node_count()
    total_edges = graph.get_edge_count()
    print(f"nodes: {total_nodes}  edges: {total_edges}", file=sys.stderr)
    for kind in ("AZDevice", "MDE_CVE", "AZUser", "User", "MDE_User"):
        n = len(graph.get_nodes_by_kind(kind))
        if n:
            print(f"  {kind}: {n}", file=sys.stderr)

    indent = args.indent if args.indent > 0 else None
    json_out = graph.export_json(include_metadata=False, indent=indent)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json_out)
        print(f"written to {out_path}", file=sys.stderr)
    else:
        print(json_out)


if __name__ == "__main__":
    main()
