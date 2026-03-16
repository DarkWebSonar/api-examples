#!/usr/bin/env python3
"""
List or search threat actor profiles from the DarkWebSonar API.
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
    parser = argparse.ArgumentParser(description="List threat actor profiles from DarkWebSonar API")
    parser.add_argument("--name", help="Filter by name (partial match)")
    parser.add_argument("--network", help="Filter by network")
    parser.add_argument("--skip", type=int, default=0, help="Number of results to skip (default: 0)")
    parser.add_argument("--limit", type=int, help="Max results (max 1000)")
    parser.add_argument("--victim-country", action="append", metavar="NAME", help="Filter by victim country (repeat for multiple)")
    parser.add_argument("--victim-country-code", action="append", metavar="CODE", help="Filter by victim country code (repeat for multiple)")
    parser.add_argument("--victim-industry", action="append", metavar="NAME", help="Filter by victim industry (repeat for multiple)")
    parser.add_argument("--category", help="Filter by attack category")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.skip < 0:
        print("Error: --skip must be >= 0.", file=sys.stderr)
        sys.exit(1)
    if args.limit is not None and (args.limit < 1 or args.limit > 1000):
        print("Error: --limit must be between 1 and 1000.", file=sys.stderr)
        sys.exit(1)

    api_key = get_api_key()
    url = f"{BASE_URL.rstrip('/')}/threat_actors/"
    headers = {"X-API-Key": api_key}
    params = {"skip": args.skip}
    if args.limit is not None:
        params["limit"] = args.limit
    if args.name:
        params["name"] = args.name
    if args.network:
        params["network"] = args.network
    if args.victim_country:
        params["victim_country"] = args.victim_country
    if args.victim_country_code:
        params["victim_country_code"] = args.victim_country_code
    if args.victim_industry:
        params["victim_industry"] = args.victim_industry
    if args.category:
        params["category"] = args.category

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

    if not data:
        print("No threat actors found.")
        return
    print(f"{'id':>6}  {'name':<35}  {'first_seen':>12}  {'last_seen':>12}  {'network':<12}  {'bad_karma':>6}")
    print("-" * 90)
    for row in data:
        id_ = row.get("id", "")
        name = (row.get("name") or "")[:34]
        first = (row.get("first_seen") or "")[:10]
        last = (row.get("last_seen") or "")[:10]
        network = (row.get("network") or "")[:11]
        karma = row.get("bad_karma", "")
        print(f"{id_:>6}  {name:<35}  {first:>12}  {last:>12}  {network:<12}  {karma:>6}")


if __name__ == "__main__":
    main()
