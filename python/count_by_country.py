#!/usr/bin/env python3
"""
Get threat counts by victim country from the DarkWebSonar API.
"""
import argparse
import json
import os
import sys

import requests

BASE_URL = os.environ.get("DWS_BASE_URL", "https://api.darkwebsonar.io")


def get_api_key():
    key = os.environ.get("DWS_API_KEY") or os.environ.get("DARKWEBSONAR_API_KEY")
    if not key:
        print("Error: Set DWS_API_KEY or DARKWEBSONAR_API_KEY in the environment.", file=sys.stderr)
        sys.exit(1)
    return key


def main():
    parser = argparse.ArgumentParser(description="Threat count by country from DarkWebSonar API")
    parser.add_argument("--time-range", help="Time range: 24h, 7d, 30d, 90d, 180d, 365d, 730d")
    parser.add_argument("--limit", type=int, help="Max countries to return (max 1000)")
    parser.add_argument("--category", help="Filter by category")
    parser.add_argument("--threat-actors", help="Filter by threat actor")
    parser.add_argument("--victim-industry", action="append", metavar="NAME", help="Filter by victim industry (repeat for multiple)")
    parser.add_argument("--victim-country-code", action="append", metavar="CODE", help="Filter by victim country code (repeat for multiple)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.limit is not None and (args.limit < 1 or args.limit > 1000):
        print("Error: --limit must be between 1 and 1000.", file=sys.stderr)
        sys.exit(1)

    api_key = get_api_key()
    url = f"{BASE_URL.rstrip('/')}/entries/count_by_country"
    headers = {"X-API-Key": api_key}
    params = {}
    if args.time_range:
        params["time_range"] = args.time_range
    if args.limit is not None:
        params["limit"] = args.limit
    if args.category:
        params["category"] = args.category
    if args.threat_actors:
        params["threat_actors"] = args.threat_actors
    if args.victim_industry:
        params["victim_industry"] = args.victim_industry
    if args.victim_country_code:
        params["victim_country_code"] = args.victim_country_code

    try:
        r = requests.get(url, headers=headers, params=params or None, timeout=30)
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

    print(f"{'victim_country':<30}  {'victim_country_code':>6}  {'count':>8}")
    print("-" * 50)
    for row in data:
        country = row.get("victim_country") or ""
        code = row.get("victim_country_code") or ""
        count = row.get("count", 0)
        print(f"{country:<30}  {code:>6}  {count:>8}")


if __name__ == "__main__":
    main()
