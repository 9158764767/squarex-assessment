# """
# Build local DuckDB and stage events from ./data JSON files.
#
# - Reads all *.json / *.jsonl under data/
# - Normalizes columns to: ts (TIMESTAMP), user_id, domain, url, app, clipboard_text
# - Infers app from domain if missing (APP_MAP)
# - Classifies clipboard_text into categories and creates sensitive_events table
# """
#
# import duckdb, json, os, glob, re
# import pandas as pd
# from dateutil import parser as dtparser
# from pathlib import Path
# from typing import Dict, Any, List
# from classify_sensitive import classify_text
#
# ROOT = Path(__file__).resolve().parents[1]
# DATA_DIR = ROOT / "data"
# DB_PATH = ROOT / "db" / "squarex.duckdb"
#
# TEXT_FIELDS = ["clipboard_text", "clipboard", "text", "content", "payload"]
# TIME_FIELDS = ["timestamp", "time", "ts", "event_time"]
# USER_FIELDS = ["user_id", "uid", "employee", "employee_id"]
# URL_FIELDS  = ["url", "uri", "full_url"]
# DOM_FIELDS  = ["domain", "host", "hostname", "site"]
# APP_FIELDS  = ["app", "application", "service"]
#
# # Heuristic domain->App mapping
# APP_MAP = {
#     r"chatgpt\.com|openai\.com": "ChatGPT",
#     r"claude\.ai|anthropic\.com": "Claude",
#     r"gemini\.google\.com|ai\.google\.com|bard\.google\.com": "Gemini",
#     r"copilot\.microsoft\.com|bing\.com": "Copilot",
#     r"dropbox\.com": "Dropbox",
#     r"drive\.google\.com|docs\.google\.com": "Google Drive",
#     r"box\.com": "Box",
#     r"wetransfer\.com": "WeTransfer",
#     r"github\.com|gitlab\.com|bitbucket\.org": "Code Hosting",
#     r"slack\.com": "Slack",
#     r"notion\.so": "Notion",
#     r"zoom\.us|zoom\.com": "Zoom",
#     r"teams\.microsoft\.com": "MS Teams",
#     r"figma\.com": "Figma",
#     r"atlassian\.com|jira\.com|bitbucket\.org": "Atlassian",
# }
#
# def infer_app(domain: str) -> str:
#     if not domain or not isinstance(domain, str):
#         return None
#     for pat, app in APP_MAP.items():
#         if re.search(pat, domain, re.I):
#             return app
#     return None
#
# def parse_ts(value: Any):
#     if pd.isna(value):
#         return None
#     try:
#         return pd.Timestamp(dtparser.parse(str(value)))
#     except Exception:
#         return None
#
# def first_present(d: Dict[str, Any], keys: List[str], default=None):
#     for k in keys:
#         if k in d:
#             return d[k]
#     return default
#
# def normalize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
#     ts = parse_ts(first_present(rec, TIME_FIELDS))
#     user_id = first_present(rec, USER_FIELDS)
#     url = first_present(rec, URL_FIELDS)
#     domain = first_present(rec, DOM_FIELDS)
#     app = first_present(rec, APP_FIELDS)
#
#     # Derive domain from URL if not present
#     if not domain and url:
#         m = re.search(r"https?://([^/]+)", str(url))
#         if m:
#             domain = m.group(1).lower()
#
#     if not app:
#         app = infer_app(domain)
#
#     text = first_present(rec, TEXT_FIELDS)
#
#     return {
#         "ts": ts,
#         "user_id": str(user_id) if user_id is not None else None,
#         "url": url,
#         "domain": domain.lower() if isinstance(domain, str) else None,
#         "app": app,
#         "clipboard_text": text
#     }
#
# def read_any_json(path: str) -> List[Dict[str, Any]]:
#     # Support array JSON or JSONL
#     out = []
#     with open(path, "r", encoding="utf-8", errors="ignore") as f:
#         first_char = f.read(1)
#         f.seek(0)
#         if first_char == "[":
#             arr = json.load(f)
#             if isinstance(arr, list):
#                 out.extend(arr)
#         else:
#             for line in f:
#                 line = line.strip()
#                 if not line:
#                     continue
#                 try:
#                     out.append(json.loads(line))
#                 except Exception:
#                     pass
#     return out
#
# def main():
#     files = []
#     for ext in ("*.json", "*.jsonl"):
#         files.extend(glob.glob(str(DATA_DIR / ext)))
#
#     if not files:
#         print(f"[WARN] No JSON files found in {DATA_DIR}. Add your data and re-run.")
#     records = []
#     for p in files:
#         for rec in read_any_json(p):
#             records.append(normalize_record(rec))
#
#     df = pd.DataFrame.from_records(records)
#     # Drop rows without timestamp or user
#     if not df.empty:
#         df = df.dropna(subset=["ts", "user_id"])
#
#     con = duckdb.connect(DB_PATH)
#     con.execute("INSTALL json; LOAD json;")
#     con.execute("PRAGMA threads=4;")
#
#     # Register functions
#     con.create_function("infer_app_from_domain", infer_app, ["VARCHAR"], "VARCHAR")
#
#     # Create base table
#     con.execute("""
#         CREATE OR REPLACE TABLE events AS
#         SELECT * FROM df
#     """)  # duckdb can import pandas DataFrame
#
#     # Enriched view with inferred app
#     # Replace the previous CREATE TABLE / INSERT ... ON CONFLICT block with:
#     con.execute("""
#         CREATE OR REPLACE TABLE app_risk_weight AS
#         SELECT * FROM (
#             VALUES
#                 ('ChatGPT', 3.0),
#                 ('Claude', 3.0),
#                 ('Gemini', 3.0),
#                 ('Copilot', 2.5),
#                 ('Dropbox', 2.0),
#                 ('Google Drive', 2.0),
#                 ('Box', 2.0),
#                 ('WeTransfer', 2.5),
#                 ('Slack', 1.5),
#                 ('Notion', 1.5),
#                 ('Atlassian', 1.0),
#                 ('Figma', 1.0),
#                 ('Zoom', 1.0),
#                 ('MS Teams', 1.0),
#                 ('Code Hosting', 2.0)
#         ) AS t(app_name, weight);
#     """)
#
#     # Sensitive events table (explode categories)
#     sens_rows = []
#     for i, row in df.iterrows():
#         cats = classify_text(row.get("clipboard_text"))
#         for c in cats:
#             sens_rows.append({
#                 "ts": row.get("ts"),
#                 "user_id": row.get("user_id"),
#                 "domain": row.get("domain"),
#                 "app_name": row.get("app") or infer_app(row.get("domain") or ""),
#                 "category": c
#             })
#     sdf = pd.DataFrame(sens_rows)
#     if sdf.empty:
#         sdf = pd.DataFrame(columns=["ts","user_id","domain","app_name","category"])
#     con.execute("CREATE OR REPLACE TABLE sensitive_events AS SELECT * FROM sdf")
#
#     # Helpful daily aggregates
#     con.execute("""
#         CREATE OR REPLACE VIEW daily_app_usage AS
#         SELECT
#           date_trunc('day', ts) AS day,
#           app_name,
#           COUNT(*) AS events,
#           COUNT(DISTINCT user_id) AS users
#         FROM events_enriched
#         GROUP BY 1,2
#         ORDER BY 1,2
#     """)
#
#     con.execute("""
#         CREATE OR REPLACE VIEW daily_sensitive_counts AS
#         SELECT
#           date_trunc('day', ts) AS day,
#           category,
#           COUNT(*) AS cnt
#         FROM sensitive_events
#         GROUP BY 1,2
#         ORDER BY 1,2
#     """)
#
#     print(f"[OK] Built DuckDB at {DB_PATH}")
#     print("[INFO] Tables: events, events_enriched, sensitive_events")
#     print("[INFO] Views: daily_app_usage, daily_sensitive_counts")
#
# if __name__ == "__main__":
#     main()



# ===================================================================================

"""
Build local DuckDB and stage events from ./data JSON files.

- Reads all *.json / *.jsonl under data/
- Normalizes columns to: ts (TIMESTAMP), user_id, domain, url, app, clipboard_text
- Infers app from domain if missing (APP_MAP)
- Classifies clipboard_text into categories and creates sensitive_events table
- Materializes events_enriched -> events_enriched_mat to avoid UDF dependency later
"""

import os, glob, json, re
from pathlib import Path
from typing import Dict, Any, List

import duckdb
import pandas as pd
from dateutil import parser as dtparser
from typing import Dict, Any, List, Optional

from classify_sensitive import classify_text

# --- Paths ---
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_DIR = ROOT / "db"
OUT_DIR = ROOT / "outputs"
DB_PATH = DB_DIR / "squarex.duckdb"

# Ensure folders exist
for d in (DATA_DIR, DB_DIR, OUT_DIR):
    d.mkdir(parents=True, exist_ok=True)

# --- Field name fallbacks (flexible schemas) ---
TEXT_FIELDS = ["clipboard_text", "clipboard", "text", "content", "payload"]
TIME_FIELDS = ["timestamp", "time", "ts", "event_time"]
USER_FIELDS = ["user_id", "uid", "employee", "employee_id"]
URL_FIELDS  = ["url", "uri", "full_url"]
DOM_FIELDS  = ["domain", "host", "hostname", "site"]
APP_FIELDS  = ["app", "application", "service"]

# --- Heuristic domain->App mapping ---
APP_MAP = {
    r"chatgpt\.com|openai\.com": "ChatGPT",
    r"claude\.ai|anthropic\.com": "Claude",
    r"gemini\.google\.com|ai\.google\.com|bard\.google\.com": "Gemini",
    r"copilot\.microsoft\.com|bing\.com": "Copilot",
    r"dropbox\.com": "Dropbox",
    r"drive\.google\.com|docs\.google\.com": "Google Drive",
    r"box\.com": "Box",
    r"wetransfer\.com": "WeTransfer",
    r"github\.com|gitlab\.com|bitbucket\.org": "Code Hosting",
    r"slack\.com": "Slack",
    r"notion\.so": "Notion",
    r"zoom\.us|zoom\.com": "Zoom",
    r"teams\.microsoft\.com": "MS Teams",
    r"figma\.com": "Figma",
    r"atlassian\.com|jira\.com|bitbucket\.org": "Atlassian",
}

def infer_app(domain: str) -> Optional[str]:
    if not domain or not isinstance(domain, str):
        return None
    for pat, app in APP_MAP.items():
        if re.search(pat, domain, re.I):
            return app
    return None

def parse_ts(value: Any):
    if pd.isna(value):
        return None
    try:
        return pd.Timestamp(dtparser.parse(str(value)))
    except Exception:
        return None

def first_present(d: Dict[str, Any], keys: List[str], default=None):
    for k in keys:
        if k in d:
            return d[k]
    return default

def normalize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    ts = parse_ts(first_present(rec, TIME_FIELDS))
    user_id = first_present(rec, USER_FIELDS)
    url = first_present(rec, URL_FIELDS)
    domain = first_present(rec, DOM_FIELDS)
    app = first_present(rec, APP_FIELDS)

    # Derive domain from URL if not present
    if not domain and url:
        m = re.search(r"https?://([^/]+)", str(url))
        if m:
            domain = m.group(1).lower()

    if not app:
        app = infer_app(domain)

    text = first_present(rec, TEXT_FIELDS)

    return {
        "ts": ts,
        "user_id": str(user_id) if user_id is not None else None,
        "url": url,
        "domain": domain.lower() if isinstance(domain, str) else None,
        "app": app,
        "clipboard_text": text
    }

def read_any_json(path: str) -> List[Dict[str, Any]]:
    """Support array JSON or JSONL."""
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        first_char = f.read(1)
        f.seek(0)
        if first_char == "[":
            arr = json.load(f)
            if isinstance(arr, list):
                out.extend(arr)
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out

def main():
    # --- Load data files ---
    files: List[str] = []
    for ext in ("*.json", "*.jsonl"):
        files.extend(glob.glob(str(DATA_DIR / ext)))

    if not files:
        print(f"[WARN] No JSON files found in {DATA_DIR}. Add your data and re-run.")

    records: List[Dict[str, Any]] = []
    for p in files:
        for rec in read_any_json(p):
            records.append(normalize_record(rec))

    df = pd.DataFrame.from_records(records)
    if not df.empty:
        # Drop rows without timestamp or user
        df = df.dropna(subset=["ts", "user_id"])

    # --- Build DuckDB ---
    con = duckdb.connect(DB_PATH)
    con.execute("INSTALL json; LOAD json;")
    con.execute("PRAGMA threads=4;")

    # Register UDF for this session
    con.create_function(
        "infer_app_from_domain",
        infer_app,
        ["VARCHAR"],
        "VARCHAR",
        null_handling="special"  # allow NULLs in/out
    )

    # Base table
    con.execute("""
        CREATE OR REPLACE TABLE events AS
        SELECT * FROM df
    """)  # DuckDB can import pandas DataFrame directly

    # Enriched view using UDF
    con.execute("""
        CREATE OR REPLACE VIEW events_enriched AS
        SELECT
          ts,
          user_id,
          url,
          domain,
          COALESCE(app, infer_app_from_domain(domain)) AS app_name,
          clipboard_text
        FROM events
    """)

    # MATERIALIZE to avoid UDF dependency in other sessions
    con.execute("""
        CREATE OR REPLACE TABLE events_enriched_mat AS
        SELECT * FROM events_enriched
    """)

    # Static weight table for risk scoring
    con.execute("""
        CREATE OR REPLACE TABLE app_risk_weight AS
        SELECT * FROM (
            VALUES
                ('ChatGPT', 3.0),
                ('Claude', 3.0),
                ('Gemini', 3.0),
                ('Copilot', 2.5),
                ('Dropbox', 2.0),
                ('Google Drive', 2.0),
                ('Box', 2.0),
                ('WeTransfer', 2.5),
                ('Slack', 1.5),
                ('Notion', 1.5),
                ('Atlassian', 1.0),
                ('Figma', 1.0),
                ('Zoom', 1.0),
                ('MS Teams', 1.0),
                ('Code Hosting', 2.0)
        ) AS t(app_name, weight);
    """)

    # Sensitive events table (explode classifier categories)
    sens_rows: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        cats = classify_text(row.get("clipboard_text"))
        for c in cats:
            sens_rows.append({
                "ts": row.get("ts"),
                "user_id": row.get("user_id"),
                "domain": row.get("domain"),
                "app_name": row.get("app") or infer_app(row.get("domain") or ""),
                "category": c
            })
    sdf = pd.DataFrame(sens_rows)
    if sdf.empty:
        sdf = pd.DataFrame(columns=["ts", "user_id", "domain", "app_name", "category"])
    con.execute("CREATE OR REPLACE TABLE sensitive_events AS SELECT * FROM sdf")

    # Helpful daily aggregates
    con.execute("""
        CREATE OR REPLACE VIEW daily_app_usage AS
        SELECT
          date_trunc('day', ts) AS day,
          app_name,
          COUNT(*) AS events,
          COUNT(DISTINCT user_id) AS users
        FROM events_enriched_mat
        GROUP BY 1,2
        ORDER BY 1,2
    """)

    con.execute("""
        CREATE OR REPLACE VIEW daily_sensitive_counts AS
        SELECT
          date_trunc('day', ts) AS day,
          category,
          COUNT(*) AS cnt
        FROM sensitive_events
        GROUP BY 1,2
        ORDER BY 1,2
    """)

    print(f"[OK] Built DuckDB at {DB_PATH}")
    print("[INFO] Tables: events, events_enriched_mat, sensitive_events, app_risk_weight")
    print("[INFO] Views: events_enriched, daily_app_usage, daily_sensitive_counts")

if __name__ == "__main__":
    main()
