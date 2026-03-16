# Python samples

Run the scripts from the **repository root** so that the `python` directory is on the path and imports work:

```bash
# From api-examples/
pip install -r requirements.txt
export DWS_API_KEY="your-api-key"

python python/get_recent_entries.py
python python/get_recent_entries.py --time-range 30d --limit 5 --category "Ransomware"
python python/get_recent_entries.py --search "breach" --all --json

python python/count_by_field.py --group-by category --time-range 7d
python python/count_by_field.py --group-by threat_actors --time-range 30d --limit 20

python python/count_by_country.py --time-range 30d --limit 20
python python/count_by_country.py --category "Data Breach" --json

python python/get_threat_actor_profiles.py --limit 10
python python/get_threat_actor_profiles.py --name "lockbit" --json
```

Optional: set `DWS_BASE_URL` to use a different base URL (e.g. staging).
