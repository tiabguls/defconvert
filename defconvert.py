#!/usr/bin/env python3
"""
defconvert.py — Convert defclone.py JSON output to BloodHound OpenGraph format.

Input:  JSON file produced by defclone.py (dict keyed by Entra device GUID)
Output: BloodHound OpenGraph JSON

Node kinds emitted
  MDE_CVE   — Unique vulnerability; ID = CVE ID string (e.g. CVE-2021-34527)
  AZUser    — Entra user with a known aadUserId; ID = Entra user GUID
              Merges with existing AZUser nodes in BloodHound.
  User      — AD user with a known accountSid but no aadUserId; ID = accountSid.
              Merges with existing AD User nodes in BloodHound by SID.
  MDE_User  — Local/unknown user with no aadUserId and no accountSid;
              ID = DOMAIN\\accountName (synthetic, no existing BH match guaranteed).

AZDevice nodes are NOT emitted. Both edges use property matching on the
existing AZDevice node's "deviceId" property to locate the correct device.

Edges emitted
  MDE_CVE   -[MDE_FoundOn]->    AZDevice  (end matched by deviceId property)
  AZDevice  -[MDE_LoggedOnTo]-> AZUser | User | MDE_User
              (start matched by deviceId property)
"""

import argparse
import json
import sys
from pathlib import Path

from bhopengraph import Node, OpenGraph, Properties


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
      3. DOMAIN\\name       → MDE_User (synthetic node; no existing BH match guaranteed)
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


# ---------------------------------------------------------------------------
# Edge dict builders (AZDevice endpoints matched by property)
# ---------------------------------------------------------------------------

def _azdevice_endpoint(entra_id: str) -> dict:
    """Property-matched edge endpoint that resolves to an existing AZDevice node."""
    return {
        "match_by": "property",
        "kind": "AZDevice",
        "property_matchers": [
            {"key": "deviceid", "operator": "equals", "value": entra_id}
        ],
    }


def _make_foundon_edge_dict(cve_id: str, entra_id: str) -> dict:
    return {
        "kind": "MDE_FoundOn",
        "start": {"value": cve_id, "match_by": "id"},
        "end": _azdevice_endpoint(entra_id),
    }


def _make_loggedon_edge_dict(entra_id: str, user: dict) -> dict:
    user_id, _ = _resolve_user_id_and_kind(user)
    props = Properties()
    _set_if(props, "firstSeen", user.get("firstSeen"))
    _set_if(props, "lastSeen",  user.get("lastSeen"))
    _set_str_list(props, "logonTypes", user.get("logonTypes"))
    edge: dict = {
        "kind": "MDE_LoggedOnTo",
        "start": _azdevice_endpoint(entra_id),
        "end": {"value": user_id, "match_by": "id"},
    }
    if len(props) > 0:
        edge["properties"] = props.to_dict()
    return edge


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def convert(data: dict) -> tuple[OpenGraph, list[dict]]:
    """
    Returns a graph of non-AZDevice nodes and a list of raw edge dicts.
    AZDevice nodes are not emitted; edges reference them via property matching.
    """
    graph = OpenGraph()
    raw_edges: list[dict] = []
    seen_edges: set[tuple] = set()

    for entra_id, entry in data.items():
        vulns = entry.get("vulnerabilities") or []
        users = entry.get("logonUsers") or []

        # CVE nodes + FoundOn edges
        for vuln in vulns:
            cve_id = vuln.get("id")
            if not cve_id:
                continue
            graph.add_node(make_cve_node(vuln))
            key = ("MDE_FoundOn", cve_id, entra_id)
            if key not in seen_edges:
                seen_edges.add(key)
                raw_edges.append(_make_foundon_edge_dict(cve_id, entra_id))

        # User nodes + LoggedOnTo edges
        for user in users:
            graph.add_node(make_user_node(user))
            user_id, _ = _resolve_user_id_and_kind(user)
            key = ("MDE_LoggedOnTo", entra_id, user_id)
            if key not in seen_edges:
                seen_edges.add(key)
                raw_edges.append(_make_loggedon_edge_dict(entra_id, user))

    return graph, raw_edges


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

    graph, raw_edges = convert(data)

    # Summary to stderr so it doesn't pollute stdout-piped output
    total_nodes = graph.get_node_count()
    total_edges = len(raw_edges)
    total_devices = len(data)
    print(f"nodes: {total_nodes}  edges: {total_edges}", file=sys.stderr)
    print(f"  AZDevice: {total_devices} (property-matched, not emitted)", file=sys.stderr)
    for kind in ("MDE_CVE", "AZUser", "User", "MDE_User"):
        n = len(graph.get_nodes_by_kind(kind))
        if n:
            print(f"  {kind}: {n}", file=sys.stderr)

    # Build final JSON: nodes from graph + raw property-matched edge dicts
    graph_dict = json.loads(graph.export_json(include_metadata=False))
    graph_dict["graph"]["edges"] = raw_edges

    indent = args.indent if args.indent > 0 else None
    json_out = json.dumps(graph_dict, indent=indent)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json_out)
        print(f"written to {out_path}", file=sys.stderr)
    else:
        print(json_out)


if __name__ == "__main__":
    main()
