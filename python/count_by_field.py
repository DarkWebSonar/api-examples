#!/usr/bin/env python3
"""
Get threat counts grouped by a field (category, industry, threat_actors, etc.) from the DarkWebSonar API.
With time_range, response includes percent_change vs previous period.
"""
import argparse
import json
import os
import sys

import requests

BASE_URL = os.environ.get("DWS_BASE_URL", "https://api.darkwebsonar.io")
VALID_GROUP_BY = ("victim_country", "victim_country_code", "industry", "category", "threat_actors", "victim_industry")


def get_api_key():
    key = os.environ.get("DWS_API_KEY") or os.environ.get("DARKWEBSONAR_API_KEY")
    if not key:
        print("Error: Set DWS_API_KEY or DARKWEBSONAR_API_KEY in the environment.", file=sys.stderr)
        sys.exit(1)
    return key


def main():
    parser = argparse.ArgumentParser(description="Threat count by field from DarkWebSonar API")
    parser.add_argument("--group-by", required=True, choices=VALID_GROUP_BY,
                        help=f"Field to group by: {', '.join(VALID_GROUP_BY)}")
    parser.add_argument("--time-range", help="Time range: 24h, 7d, 30d, 90d, 180d, 365d, 730d")
    parser.add_argument("--limit", type=int, help="Max results (max 1000)")
    parser.add_argument("--category", help="Filter by category")
    parser.add_argument("--threat-actors", help="Filter by threat actor")
    parser.add_argument("--victim-country-code", action="append", metavar="CODE", help="Filter by victim country code (repeat for multiple)")
    parser.add_argument("--victim-country", action="append", metavar="NAME", help="Filter by victim country (repeat for multiple)")
    parser.add_argument("--victim-industry", action="append", metavar="NAME", help="Filter by victim industry (repeat for multiple)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.limit is not None and (args.limit < 1 or args.limit > 1000):
        print("Error: --limit must be between 1 and 1000.", file=sys.stderr)
        sys.exit(1)

    api_key = get_api_key()
    url = f"{BASE_URL.rstrip('/')}/entries/count_by_field"
    headers = {"X-API-Key": api_key}
    params = {"group_by": args.group_by}
    if args.time_range:
        params["time_range"] = args.time_range
    if args.limit is not None:
        params["limit"] = args.limit
    if args.category:
        params["category"] = args.category
    if args.threat_actors:
        params["threat_actors"] = args.threat_actors
    if args.victim_country_code:
        params["victim_country_code"] = args.victim_country_code
    if args.victim_country:
        params["victim_country"] = args.victim_country
    if args.victim_industry:
        params["victim_industry"] = args.victim_industry

    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    if r.status_code == 401:
        print("Error: Unauthorized (invalid or missing API key).", file=sys.stderr)
        sys.exit(1)
    if r.status_code == 403:
        print("Error: Forbidden (invalid API key, disabled key, or no remaining credits).", file=sys.stderr)
        sys.exit(1)
    if r.status_code == 429:
        print("Error: Rate limit exceeded (429). Back off and retry later.", file=sys.stderr)
        sys.exit(1)
    r.raise_for_status()

    data = r.json()

    if args.json:
        print(json.dumps(data, indent=2))
        return

    # Table-style output
    key_label = args.group_by
    has_pct = isinstance(data, list) and data and "percent_change" in (data[0] or {})
    if has_pct:
        print(f"{key_label:<30}  {'count':>8}  {'previous':>10}  {'percent_change':>14}")
        print("-" * 70)
        for row in data:
            key_val = row.get(key_label) or ""
            cnt = row.get("count", 0)
            prev = row.get("previous", "")
            pct = row.get("percent_change")
            pct_str = f"{pct:+.1f}%" if pct is not None else ""
            print(f"{str(key_val):<30}  {cnt:>8}  {str(prev):>10}  {pct_str:>14}")
    else:
        print(f"{key_label:<40}  {'count':>8}")
        print("-" * 52)
        for row in data:
            key_val = row.get(key_label) or ""
            cnt = row.get("count", 0)
            print(f"{str(key_val):<40}  {cnt:>8}")


if __name__ == "__main__":
    main()
