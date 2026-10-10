#!/usr/bin/env python3
"""
Purple-Team Detection Lab - detection checker.

Reads the UTC windows produced by run_tests.sh and, for each one, asks the Wazuh
indexer which alerts fired for the target agent. Prints a detected/missed table.

Run on the Wazuh manager host (the indexer is bound to 127.0.0.1 by default).
Edit the settings block, then:
    python3 check_detections.py results_<timestamp>.csv
"""
import csv, sys, datetime, requests, urllib3
urllib3.disable_warnings()

# --- settings ---
INDEXER  = "https://127.0.0.1:9200"
USER     = "admin"          # or a read-only indexer account
PASS     = "CHANGE_ME"      # that account's password
AGENT    = "kali-lab"       # agent.name as it shows in Wazuh
PRE_SEC  = 10               # look this many seconds before each start
POST_SEC = 120              # and after each end (pipeline lag + slow tests)
# ----------------

def parse(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

def shift(ts, secs):
    return (parse(ts) + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")

rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["technique"] != "technique"]

print(f"{'technique':<12}{'result':<10}{'top rule':<10}{'lvl':<5}description")
print("-" * 80)
for r in rows:
    start = shift(r["start_utc"], -PRE_SEC)
    end   = shift(r["end_utc"],   POST_SEC)
    q = {
        "size": 5,
        "sort": [{"rule.level": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": start, "lte": end}}},
            {"match": {"agent.name": AGENT}},
        ]}},
    }
    resp = requests.get(f"{INDEXER}/wazuh-alerts-*/_search",
                        json=q, auth=(USER, PASS), verify=False, timeout=30)
    hits = resp.json().get("hits", {}).get("hits", [])
    if hits:
        rule = hits[0]["_source"]["rule"]
        print(f"{r['technique']:<12}{'DETECTED':<10}{rule['id']:<10}{rule['level']:<5}{rule['description'][:45]}")
    else:
        print(f"{r['technique']:<12}{'MISSED':<10}{'-':<10}{'-':<5}no alert in window")
