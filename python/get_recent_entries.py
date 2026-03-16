#!/usr/bin/env python3
"""
Fetch recent threat intelligence entries from the DarkWebSonar API.
Supports filters: time_range, category, threat_actors, search, victim_country_code, etc.
Response is paginated (total, skip, limit, data). Use --all to fetch all pages.
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
    parser = argparse.ArgumentParser(description="Fetch recent threat entries from DarkWebSonar API")
    parser.add_argument("--time-range", default="7d", help="Time range: 24h, 7d, 30d, 90d, 180d, 365d, 730d (default: 7d)")
    parser.add_argument("--limit", type=int, default=10, help="Max entries per request (default: 10, max: 1000)")
    parser.add_argument("--skip", type=int, default=0, help="Number of entries to skip (default: 0)")
    parser.add_argument("--category", help="Filter by category (partial match)")
    parser.add_argument("--threat-actors", help="Filter by threat actor name (partial match)")
    parser.add_argument("--search", help="Free-text search in title, content, victim_organization, etc.")
    parser.add_argument("--victim-country-code", action="append", metavar="CODE", help="Filter by victim country code (repeat for multiple, e.g. US, GB)")
    parser.add_argument("--victim-country", action="append", metavar="NAME", help="Filter by victim country name (repeat for multiple)")
    parser.add_argument("--victim-industry", action="append", metavar="NAME", help="Filter by victim industry (repeat for multiple)")
    parser.add_argument("--all", action="store_true", help="Fetch all pages (iterate until skip >= total)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a short summary")
    args = parser.parse_args()

    if args.limit < 1 or args.limit > 1000:
        print("Error: --limit must be between 1 and 1000.", file=sys.stderr)
        sys.exit(1)
    if args.skip < 0:
        print("Error: --skip must be >= 0.", file=sys.stderr)
        sys.exit(1)

    api_key = get_api_key()
    url = f"{BASE_URL.rstrip('/')}/entries/"
    headers = {"X-API-Key": api_key}

    all_data = []
    skip = args.skip
    limit = args.limit
    total_seen = None

    while True:
        params = {"time_range": args.time_range, "limit": limit, "skip": skip}
        if args.category:
            params["category"] = args.category
        if args.threat_actors:
            params["threat_actors"] = args.threat_actors
        if args.search:
            params["search"] = args.search
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

        body = r.json()
        total = body.get("total", 0)
        total_seen = total
        data = body.get("data", [])
        all_data.extend(data)

        if not args.all or skip + len(data) >= total or len(data) == 0:
            break
        skip += len(data)

    if args.all and not args.json:
        data = all_data
        total = total_seen or 0
        skip = args.skip
        limit = len(all_data)
    else:
        data = body.get("data", [])
        total = body.get("total", 0)
        skip = body.get("skip", args.skip)
        limit = body.get("limit", args.limit)

    if args.json:
        if args.all:
            print(json.dumps({"total": total, "skip": args.skip, "limit": len(all_data), "data": all_data}, indent=2))
        else:
            print(json.dumps(body, indent=2))
        return

    print(f"Total: {total}  Skip: {skip}  Limit: {limit}")
    print(f"Returned: {len(data)} entries")
    for i, entry in enumerate(data[:10], 1):
        title = entry.get("title") or "(no title)"
        date = entry.get("date") or entry.get("date_only") or ""
        cat = entry.get("category") or ""
        print(f"  {i}. [{cat}] {date}  {title[:70]}{'...' if len(title) > 70 else ''}")
    if len(data) > 10:
        print(f"  ... and {len(data) - 10} more")


if __name__ == "__main__":
    main()
