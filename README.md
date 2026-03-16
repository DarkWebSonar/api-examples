# DarkWebSonar API – Sample Scripts

Sample Python scripts to get started with the [DarkWebSonar API](https://darkwebsonar.io/docs/). Use them to fetch threat intelligence entries, run analytics by category or country, and list threat actor profiles.

## Prerequisites

- Python 3.7+
- Install dependencies: `pip install -r requirements.txt`

## Authentication

Set your API key in the environment (do not hardcode it in scripts):

```bash
export DWS_API_KEY="your-api-key"
# or
export DARKWEBSONAR_API_KEY="your-api-key"
```

See the [API docs](https://darkwebsonar.io/docs/) and best practices: store keys in env vars or a secrets manager, rotate them regularly, and never commit keys to version control.

## Sample scripts

| Script | Purpose |
|--------|--------|
| `python/get_recent_entries.py` | Fetch recent threat entries with optional filters (time range, category, search, country, etc.) |
| `python/count_by_field.py` | Aggregate threat counts by category, industry, or threat actors |
| `python/count_by_country.py` | Threat counts by victim country |
| `python/get_threat_actor_profiles.py` | List or search threat actor profiles |

Run from the repo root, for example:

```bash
python python/get_recent_entries.py
python python/get_recent_entries.py --time-range 30d --limit 5 --category "Ransomware"
python python/count_by_field.py --group-by category --time-range 7d
python python/count_by_country.py --time-range 30d --limit 20
python python/get_threat_actor_profiles.py --limit 10
```

## API reference

- [DarkWebSonar API Reference](https://darkwebsonar.io/docs/)

## Rate limits

Respect your plan’s rate limits. If you receive `429 Too Many Requests`, back off and retry (e.g. with exponential backoff). The samples do not implement retries; add them in production code as needed.
