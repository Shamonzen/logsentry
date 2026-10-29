"""Group alerts from one /24 (IPv6: /64) that overlap in time into campaigns."""

import sqlite3
from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import NamedTuple

from logsentry import store


class Campaign(NamedTuple):
    subnet: str
    first_seen: datetime
    last_seen: datetime
    ip_count: int
    alert_ids: list[int]
    categories: list[str]


def subnet(ip: str) -> IPv4Network | IPv6Network:
    prefix = 24 if ip_address(ip).version == 4 else 64
    return ip_network(f"{ip}/{prefix}", strict=False)


def group(alerts: list[dict], gap: timedelta) -> list[Campaign]:
    """Campaigns among stored alerts (dicts with id, src_ip, first_seen, last_seen, ...).

    Within a subnet, an alert joins the current chain when it starts at most `gap` after the
    chain's latest `last_seen`. A chain becomes a campaign once it holds 2+ distinct IPs.
    """
    by_subnet: dict[IPv4Network | IPv6Network, list[dict]] = {}
    for a in alerts:
        by_subnet.setdefault(subnet(a["src_ip"]), []).append(a)
    campaigns = []
    for net, members in by_subnet.items():
        chains: list[list[dict]] = []
        end = None  # latest last_seen in the current chain
        for a in sorted(members, key=lambda a: a["first_seen"]):
            if end is not None and a["first_seen"] - end <= gap:
                chains[-1].append(a)
                end = max(end, a["last_seen"])
            else:
                chains.append([a])
                end = a["last_seen"]
        for chain in chains:
            ips = {a["src_ip"] for a in chain}
            if len(ips) < 2:
                continue
            # web alerts list their categories; other rules contribute their rule name
            names = [c for a in chain for c in (a["categories"] or [a["rule_name"]])]
            campaigns.append(
                Campaign(
                    subnet=str(net),
                    first_seen=min(a["first_seen"] for a in chain),
                    last_seen=max(a["last_seen"] for a in chain),
                    ip_count=len(ips),
                    alert_ids=[a["id"] for a in chain],
                    categories=list(dict.fromkeys(names)),
                )
            )
    return campaigns


def rebuild(conn: sqlite3.Connection, gap: timedelta) -> list[Campaign]:
    """Recompute every campaign from the stored alerts and save them."""
    # shortcut: recomputed from all alerts and ids change on each rebuild; fine at lab scale,
    # make it incremental (and ids stable) if the alerts table grows large
    campaigns = group(store.campaign_inputs(conn), gap)
    store.save_campaigns(conn, campaigns)
    return campaigns
