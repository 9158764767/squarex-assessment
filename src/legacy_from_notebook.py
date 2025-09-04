



import json, os, duckdb, pandas as pd
# from google.colab import files

os.makedirs('/content/project/data', exist_ok=True)
DB_PATH = '/content/project/data/events.duckdb'
RAW_JSON = '/content/Sample Data.json'  # we'll upload this next


print("Upload your NDJSON file (e.g., 'Sample Data.json'):")
uploaded = files.upload()  # pick your local NDJSON
RAW_JSON = '/content/' + list(uploaded.keys())[0]
print("Got:", RAW_JSON)


# Read NDJSON robustly (line-by-line)
rows = []
with open(RAW_JSON, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass

df = pd.DataFrame(rows)
print("Rows:", len(df), "Cols:", len(df.columns))

con = duckdb.connect(DB_PATH)
con.execute("INSTALL 'json'; LOAD 'json';")  # not strictly required but handy
con.register('staging', df)

con.execute("""
CREATE OR REPLACE TABLE events AS
SELECT * FROM staging
""")

# basic sanity
print(con.execute("SELECT COUNT(*) AS rows FROM events").fetchdf())


# Read NDJSON robustly (line-by-line)
rows = []
with open(RAW_JSON, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass

df = pd.DataFrame(rows)
print("Rows:", len(df), "Cols:", len(df.columns))

con = duckdb.connect(DB_PATH)
con.execute("INSTALL 'json'; LOAD 'json';")  # not strictly required but handy
con.register('staging', df)

con.execute("""
CREATE OR REPLACE TABLE events AS
SELECT * FROM staging
""")

# basic sanity
print(con.execute("SELECT COUNT(*) AS rows FROM events").fetchdf())


print(con.execute("""
SELECT class, COUNT(*) AS n
FROM events
GROUP BY 1 ORDER BY n DESC
""").fetchdf())

print(con.execute("""
SELECT severity, COUNT(*) AS n
FROM events
GROUP BY 1 ORDER BY n DESC
""").fetchdf())

print(con.execute("""
SELECT COUNT(*) AS null_domain
FROM events WHERE domain IS NULL OR domain=''
""").fetchdf())


# Optional deeper EDA; safe to skip if you want
print(con.execute("""
SELECT url, hostname, class, COUNT(*) AS n
FROM events
WHERE (domain IS NULL OR domain = '')
GROUP BY 1,2,3
ORDER BY n DESC
""").fetchdf())

print(con.execute("""
SELECT class, attacks_type, attacks_detector, domain, COUNT(*) AS n
FROM events
WHERE severity IN ('HIGH','CRITICAL')
GROUP BY 1,2,3,4
ORDER BY n DESC, class
""").fetchdf())

print(con.execute("""
SELECT
  COALESCE(identity_method,'(unknown)') AS method,
  COALESCE(identity_provider,'(unknown)') AS provider,
  COUNT(*) AS events
FROM events
WHERE class='identity'
GROUP BY 1,2
ORDER BY events DESC
""").fetchdf())


# Drop any previous version (idempotent)
con.execute("DROP VIEW IF EXISTS cleaned_events;")

# Inspect the schema of `events`
cols_df = con.execute("PRAGMA table_info('events')").fetchdf()
cols = set(cols_df['name'].tolist())

def has(c): return c in cols
missing = []

def expr_bool(src, alias=None, default_false=True):
    alias = alias or src
    if has(src):
        return f"COALESCE(e.{src}, {'FALSE' if default_false else 'NULL'}) AS {alias}"
    else:
        missing.append(src); return f"CAST(FALSE AS BOOLEAN) AS {alias}"

def expr_text(src, alias=None):
    alias = alias or src
    if has(src): return f"e.{src} AS {alias}"
    else: missing.append(src); return f"CAST(NULL AS VARCHAR) AS {alias}"

def expr_any(src, alias=None):
    alias = alias or src
    if has(src): return f"e.{src} AS {alias}"
    else: missing.append(src); return f"NULL AS {alias}"

select_parts = []

# Core ids
for c in ["event_id","user_id","name","email","class","action","severity","effect","hostname","url"]:
    select_parts.append(expr_any(c))

# Timestamp
select_parts.append("TRY_CAST(e.timestamp AS TIMESTAMP) AS ts" if has("timestamp")
                    else "CAST(NULL AS TIMESTAMP) AS ts")

# Domain
select_parts.append("lower(e.domain) AS domain" if has("domain")
                    else "CAST(NULL AS VARCHAR) AS domain")

# url_domain_age_days (use regexp_matches for portability)
if has("url_domain_age"):
    select_parts.append(
        "CASE WHEN regexp_matches(e.url_domain_age, '^[0-9]+$') "
        "THEN CAST(e.url_domain_age AS INTEGER) END AS url_domain_age_days"
    )
else:
    missing.append("url_domain_age"); select_parts.append("CAST(NULL AS INTEGER) AS url_domain_age_days")

# URL flags (these may not exist → default FALSE)
for b in ["url_known_malicious","url_free_hosting","url_contains_unicode","url_typosquatting","url_top_domain"]:
    select_parts.append(expr_bool(b))

# Page/meta
for t in ["page_referrer_url","page_content_category","url_category"]:
    select_parts.append(expr_text(t))

# Identity
for t in ["identity_username","identity_email","identity_domain","identity_provider","identity_method","identity_url"]:
    select_parts.append(expr_text(t))
select_parts.append(expr_bool("identity_password_reuse"))

# Clipboard
for t in ["clipboard_text","clipboard_text_hash","clipboard_source_type",
          "clipboard_source_url","clipboard_source_hostname","clipboard_source_url_category"]:
    select_parts.append(expr_text(t))

# Detection / Threat
for t in ["detection_classes","detection_methods","ioc","attacks_type","attacks_subtype","attacks_detector"]:
    select_parts.append(expr_text(t))

# Device
for t in ["browser_name","browser_version","os_name","os_version"]:
    select_parts.append(expr_text(t))

select_sql = ",\n  ".join(select_parts)
sql_cleaned = f"""
CREATE OR REPLACE VIEW cleaned_events AS
SELECT
  {select_sql}
FROM events e;
"""
con.execute(sql_cleaned)

print("✅ cleaned_events created.")


con.execute("DROP VIEW IF EXISTS cleaned_events_plus;")
con.execute("""
CREATE OR REPLACE VIEW cleaned_events_plus AS
SELECT
  ce.*,
  COALESCE(
    ce.clipboard_text_hash,
    CASE WHEN ce.clipboard_text IS NOT NULL THEN hash(ce.clipboard_text) END
  ) AS clip_hash
FROM cleaned_events ce;
""")
print("✅ cleaned_events_plus created (with clip_hash).")


con.execute("""
CREATE OR REPLACE VIEW saas_usage AS
SELECT
  domain AS app_domain,
  COUNT(*) AS total_events,
  COUNT(DISTINCT user_id) AS distinct_users,
  SUM(CASE WHEN class='identity' THEN 1 ELSE 0 END) AS login_events,
  MIN(ts) AS first_seen,
  MAX(ts) AS last_seen
FROM cleaned_events
WHERE domain IS NOT NULL AND domain <> ''
GROUP BY 1;

CREATE OR REPLACE VIEW saas_risk_flags AS
SELECT
  domain AS app_domain,
  BOOL_OR(url_known_malicious) AS f_known_malicious,
  BOOL_OR(url_free_hosting) AS f_free_hosting,
  BOOL_OR(url_contains_unicode) AS f_contains_unicode,
  BOOL_OR(url_typosquatting) AS f_typosquatting,
  MIN(COALESCE(url_domain_age_days, 999999)) AS min_domain_age_days,
  BOOL_OR(severity IN ('HIGH','CRITICAL')) AS f_high_sev_any,
  SUM(CASE WHEN class='identity' AND identity_password_reuse THEN 1 ELSE 0 END) AS reuse_hits
FROM cleaned_events
WHERE domain IS NOT NULL AND domain <> ''
GROUP BY 1;

CREATE OR REPLACE VIEW saas_overview AS
SELECT
  u.*,
  r.f_known_malicious,
  r.f_free_hosting,
  r.f_contains_unicode,
  r.f_typosquatting,
  r.min_domain_age_days,
  r.f_high_sev_any,
  r.reuse_hits,
  (CASE WHEN r.f_known_malicious THEN 5 ELSE 0 END) +
  (CASE WHEN r.f_high_sev_any THEN 4 ELSE 0 END) +
  (CASE WHEN r.min_domain_age_days < 30 THEN 3 ELSE 0 END) +
  (CASE WHEN r.f_free_hosting THEN 3 ELSE 0 END) +
  (CASE WHEN r.f_typosquatting THEN 3 ELSE 0 END) +
  (CASE WHEN r.f_contains_unicode THEN 2 ELSE 0 END) +
  (CASE WHEN r.reuse_hits > 0 THEN 2 ELSE 0 END) AS risk_score
FROM saas_usage u
LEFT JOIN saas_risk_flags r USING (app_domain);
""")
print("✅ saas_* views created.")


con.execute("""
CREATE OR REPLACE VIEW genai_domains AS
SELECT * FROM (VALUES
  ('openai.com'), ('chatgpt.com'), ('claude.ai'), ('anthropic.com'),
  ('gemini.google.com'), ('bard.google.com'), ('perplexity.ai'),
  ('copilot.microsoft.com'), ('huggingface.co')
) AS t(domain);

CREATE OR REPLACE VIEW clipboard_classification AS
WITH base AS (
  SELECT
    event_id, ts, user_id, domain, class, clipboard_text,
    clipboard_source_url_category, clipboard_source_hostname
  FROM cleaned_events
  WHERE class IN ('copy','paste') AND clipboard_text IS NOT NULL AND clipboard_text <> ''
),
rules AS (
  SELECT
    event_id,
    CASE
      WHEN regexp_matches(clipboard_text, '-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----') THEN 'SECRET: Private Key'
      WHEN regexp_matches(clipboard_text, '\\\\bAKIA[0-9A-Z]{16}\\\\b') THEN 'SECRET: AWS Access Key'
      WHEN regexp_matches(clipboard_text, '\\\\bAIza[0-9A-Za-z\\-_]{35}\\\\b') THEN 'SECRET: Google API Key'
      WHEN regexp_matches(clipboard_text, '\\\\bsk-[A-Za-z0-9]{32,}\\\\b') THEN 'SECRET: OpenAI Key'
      WHEN regexp_matches(clipboard_text, '\\\\bghp_[A-Za-z0-9]{36}\\\\b') THEN 'SECRET: GitHub PAT'
      WHEN regexp_matches(clipboard_text, '\\\\bxox[baprs]-[A-Za-z0-9-]{10,}\\\\b') THEN 'SECRET: Slack Token'
      WHEN regexp_matches(clipboard_text, '\\\\b[A-Za-z0-9\\-_]{10,}\\\\.[A-Za-z0-9\\-_]{10,}\\\\.[A-Za-z0-9\\-_]{10,}\\\\b') THEN 'SECRET: JWT'
      WHEN regexp_matches(clipboard_text, '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\\\.[A-Z]{2,}') THEN 'PII: Email Address'
      WHEN regexp_matches(clipboard_text, '(?i)\\\\+?\\\\d[\\\\d\\\\s().-]{8,}') THEN 'PII: Phone Number'
      WHEN regexp_matches(clipboard_text, '\\\\b\\\\d{1,3}(\\\\.\\\\d{1,3}){3}\\\\b') THEN 'PII: IP Address'
      WHEN regexp_matches(clipboard_text,
           '\\\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\\\\b')
           THEN 'FIN: Credit Card'
      WHEN regexp_matches(clipboard_text, '\\\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\\\b') THEN 'FIN: IBAN-like'
      WHEN regexp_matches(clipboard_text, '(?i)\\\\b(invoice|iban|swift|vat|tax|amount|total)\\\\b') THEN 'FIN: Financial Terms'
      WHEN regexp_matches(clipboard_text, '(?i)\\\\b(class|def|function|import|package|public\\\\s+static|#include)\\\\b')
           OR regexp_matches(clipboard_text, '[{}();]{4,}') THEN 'CODE: Source Snippet'
      WHEN regexp_matches(clipboard_text, '(?i)\\\\b(username|password|otp|one[-\\\\s]?time|login)\\\\b') THEN 'CRED: Credential Text'
      ELSE 'OTHER'
    END AS sensitive_category
  FROM base
)
SELECT b.*, r.sensitive_category
FROM base b
JOIN rules r USING (event_id);
""")
print("✅ clipboard_classification view created.")


con.execute("""
CREATE OR REPLACE VIEW clipboard_copy_paste_links AS
WITH copies AS (
  SELECT user_id, clipboard_text_hash, ts AS copy_ts,
         clipboard_source_url, clipboard_source_hostname, clipboard_source_url_category
  FROM cleaned_events
  WHERE class='copy' AND clipboard_text_hash IS NOT NULL
),
pastes AS (
  SELECT event_id, user_id, clipboard_text_hash, ts AS paste_ts,
         domain AS dest_domain, url AS dest_url
  FROM cleaned_events
  WHERE class='paste' AND clipboard_text_hash IS NOT NULL
)
SELECT
  p.event_id,
  p.user_id,
  p.paste_ts,
  p.dest_domain,
  p.dest_url,
  c.copy_ts,
  c.clipboard_source_url,
  c.clipboard_source_hostname,
  c.clipboard_source_url_category
FROM pastes p
JOIN copies c
  ON p.user_id = c.user_id
 AND p.clipboard_text_hash = c.clipboard_text_hash""")


#test it
print(con.execute("DESCRIBE clipboard_copy_paste_links").fetchdf())
print(con.execute("SELECT COUNT(*) FROM clipboard_copy_paste_links").fetchdf())
print(con.execute("SELECT * FROM clipboard_copy_paste_links LIMIT 10").fetchdf())

# A) How many copy/paste events have a non-null clipboard_text_hash?
print(con.execute("""
SELECT class, COUNT(*) AS n_all,
       COUNT(*) FILTER (WHERE clipboard_text_hash IS NOT NULL) AS n_with_hash
FROM cleaned_events
WHERE class IN ('copy','paste')
GROUP BY 1 ORDER BY 1;
""").fetchdf())

# B) Do we have pastes into GenAI at all? (sanity)
print(con.execute("""
WITH g AS (SELECT lower(domain) AS d FROM genai_domains)
SELECT COUNT(*) AS genai_pastes
FROM cleaned_events
WHERE class='paste' AND lower(domain) IN (SELECT d FROM g);
""").fetchdf())

# C) Sample a few copy/paste rows to eyeball the fields
print(con.execute("""
SELECT class, ts, user_id, LEFT(clipboard_text, 80) AS sample, clipboard_text_hash
FROM cleaned_events
WHERE class IN ('copy','paste') AND clipboard_text IS NOT NULL
ORDER BY ts DESC
LIMIT 10;
""").fetchdf())


# Create a plus view with a derived clip_hash
con.execute("DROP VIEW IF EXISTS cleaned_events_plus;")
con.execute("""
CREATE OR REPLACE VIEW cleaned_events_plus AS
SELECT
  ce.*,
  /* Prefer existing hash; else derive from text (if present) */
  COALESCE(ce.clipboard_text_hash,
           CASE WHEN ce.clipboard_text IS NOT NULL THEN md5(ce.clipboard_text) END
  ) AS clip_hash
FROM cleaned_events ce;
""")

# If md5() is not available in your DuckDB build, uncomment this alternative:
# con.execute("""
# CREATE OR REPLACE VIEW cleaned_events_plus AS
# SELECT
#   ce.*,
#   COALESCE(ce.clipboard_text_hash,
#            CASE WHEN ce.clipboard_text IS NOT NULL THEN CAST(hash(ce.clipboard_text) AS VARCHAR) END
#   ) AS clip_hash
# FROM cleaned_events ce;
# """)

# Rebuild the linkage with clip_hash and a 2-hour window
con.execute("DROP VIEW IF EXISTS clipboard_copy_paste_links;")
con.execute("""
CREATE OR REPLACE VIEW clipboard_copy_paste_links AS
WITH copies AS (
  SELECT user_id, clip_hash, ts AS copy_ts,
         clipboard_source_url, clipboard_source_hostname, clipboard_source_url_category
  FROM cleaned_events_plus
  WHERE class='copy' AND clip_hash IS NOT NULL
),
pastes AS (
  SELECT event_id, user_id, clip_hash, ts AS paste_ts,
         domain AS dest_domain, url AS dest_url
  FROM cleaned_events_plus
  WHERE class='paste' AND clip_hash IS NOT NULL
)
SELECT
  p.event_id,
  p.user_id,
  p.paste_ts,
  p.dest_domain,
  p.dest_url,
  c.copy_ts,
  c.clipboard_source_url,
  c.clipboard_source_hostname,
  c.clipboard_source_url_category
FROM pastes p
JOIN copies c
  ON p.user_id = c.user_id
 AND p.clip_hash = c.clip_hash
 AND c.copy_ts <= p.paste_ts
 AND p.paste_ts <= c.copy_ts + INTERVAL 2 HOUR;
""")

# Check again
print(con.execute("DESCRIBE clipboard_copy_paste_links").fetchdf())
print(con.execute("SELECT COUNT(*) AS n FROM clipboard_copy_paste_links").fetchdf())


con.execute("DROP VIEW IF EXISTS clipboard_copy_paste_links;")
con.execute("""
CREATE OR REPLACE VIEW clipboard_copy_paste_links AS
WITH copies AS (
  SELECT user_id, clip_hash, ts AS copy_ts,
         clipboard_source_url, clipboard_source_hostname, clipboard_source_url_category
  FROM cleaned_events_plus
  WHERE class='copy' AND clip_hash IS NOT NULL
),
pastes AS (
  SELECT event_id, user_id, clip_hash, ts AS paste_ts,
         domain AS dest_domain, url AS dest_url
  FROM cleaned_events_plus
  WHERE class='paste' AND clip_hash IS NOT NULL
)
SELECT
  p.event_id,
  p.user_id,
  p.paste_ts,
  p.dest_domain,
  p.dest_url,
  c.copy_ts,
  c.clipboard_source_url,
  c.clipboard_source_hostname,
  c.clipboard_source_url_category
FROM pastes p
JOIN copies c
  ON p.user_id = c.user_id
 AND p.clip_hash = c.clip_hash
 AND c.copy_ts <= p.paste_ts
 AND p.paste_ts <= c.copy_ts + INTERVAL 24 HOUR;  -- widened window
""")
print(con.execute("SELECT COUNT(*) AS n FROM clipboard_copy_paste_links").fetchdf())


con.close()
print("DuckDB saved at:", DB_PATH)

from google.colab import files
files.download(DB_PATH)


import os
import duckdb
import pandas as pd
import streamlit as st
import altair as alt

# Use the absolute path for the DuckDB file
DB_PATH = "/content/project/data/events.duckdb"
# Define the SQL directory path and create it if it doesn't exist
SQL_DIR = "/content/project/sql"
os.makedirs(SQL_DIR, exist_ok=True)


st.set_page_config(page_title="SquareX Analytics – DuckDB Hybrid", layout="wide")

def run_sql_file(con, fname):
    path = os.path.join(SQL_DIR, fname)
    # Check if the SQL file exists before trying to read it
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            con.execute(f.read())
    else:
        st.warning(f"SQL file not found: {fname}") # Add a warning if file is missing


@st.cache_resource
def get_connection(db_path: str):
    con = duckdb.connect(db_path, read_only=False)
    # Ensure views exist - Note: These SQL files need to be created in the SQL_DIR
    # I've added a check in run_sql_file, but you'll need to create these files
    # in the /content/project/sql directory for this to work.
    for fname in ["10_cleaned_events.sql", "20_saas_views.sql", "30_genai_classify.sql", "40_linkage.sql"]:
        run_sql_file(con, fname)
    return con

@st.cache_data(show_spinner=False)
def df_query(con, sql, params=None):
    return con.execute(sql, params or {}).fetchdf()

st.title("SquareX Analytics (DuckDB + Colab + Streamlit)")

try:
    con = get_connection(DB_PATH)
except Exception as e:
    st.error(f"Could not open DuckDB at {DB_PATH}\n{e}")
    st.stop()

# Sidebar filters
with st.sidebar:
    st.header("Global Filters")
    minmax = df_query(con, "SELECT MIN(ts) AS min_ts, MAX(ts) AS max_ts FROM cleaned_events")
    min_ts = pd.to_datetime(minmax.loc[0, "min_ts"])
    max_ts = pd.to_datetime(minmax.loc[0, "max_ts"])
    start, end = st.date_input("Date range", (min_ts.date(), max_ts.date()))
    date_filter = f"ts >= TIMESTAMP '{start} 00:00:00' AND ts <= TIMESTAMP '{end} 23:59:59'"
    domain_search = st.text_input("Search domain contains", "", help="Partial match on domain")

tabs = st.tabs(["Task 1 — SaaS Discovery & Risk", "Task 2 — Sensitive Data to GenAI"])

# ------------- Task 1 -------------
with tabs[0]:
    st.subheader("Executive Overview")

    where = f"WHERE {date_filter}"
    params = None
    if domain_search.strip():
        where += " AND app_domain ILIKE '%' || ? || '%'"
        params = [domain_search.strip().lower()]

    # KPIs
    kpis = df_query(con, f"""
        SELECT
          COUNT(*) AS saas_apps,
          SUM(distinct_users) AS total_user_app_pairs,
          COUNT_IF(first_seen >= now() - INTERVAL 30 DAY) AS new_apps_30d
        FROM (SELECT * FROM saas_overview {where})
    """, params)

    hi_crit = df_query(con, f"""
        SELECT COUNT(*) AS hi_crit_30d
        FROM cleaned_events
        WHERE severity IN ('HIGH','CRITICAL')
          AND ts >= now() - INTERVAL 30 DAY
          AND {date_filter}
    """)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("SaaS apps observed", int(kpis.saas_apps[0]))
    c2.metric("User–app pairs", int(kpis.total_user_app_pairs[0]))
    c3.metric("New apps (30d)", int(kpis.new_apps_30d[0]))
    c4.metric("HIGH/CRITICAL (30d)", int(hi_crit.hi_crit_30d[0]))

    # Top by risk
    df_risk = df_query(con, f"""
        SELECT app_domain, distinct_users, login_events, risk_score,
               f_known_malicious, f_high_sev_any, min_domain_age_days
        FROM saas_overview
        {where}
        ORDER BY risk_score DESC, distinct_users DESC
        LIMIT 20
    """, params)

    st.markdown("**Top SaaS by Risk Score**")
    if not df_risk.empty:
        chart = alt.Chart(df_risk).mark_bar().encode(
            x=alt.X("risk_score:Q", title="Risk Score"),
            y=alt.Y("app_domain:N", sort='-x', title="SaaS App"),
            color=alt.Color("distinct_users:Q", title="Distinct Users", scale=alt.Scale(scheme='blues'))
        ).properties(height=420)
        st.altair_chart(chart, use_container_width=True)
    st.dataframe(df_risk, use_container_width=True)

    # Top by adoption
    df_adopt = df_query(con, f"""
        SELECT app_domain, distinct_users, total_events, risk_score, first_seen, last_seen
        FROM saas_overview
        {where}
        ORDER BY distinct_users DESC, total_events DESC
        LIMIT 20
    """, params)

    st.markdown("**Top SaaS by Adoption (Distinct Users)**")
    if not df_adopt.empty:
        chart2 = alt.Chart(df_adopt).mark_bar().encode(
            x=alt.X("distinct_users:Q", title="Distinct Users"),
            y=alt.Y("app_domain:N", sort='-x', title="SaaS App"),
            color=alt.Color("risk_score:Q", title="Risk Score", scale=alt.Scale(scheme='orangered'))
        ).properties(height=420)
        st.altair_chart(chart2, use_container_width=True)
    st.dataframe(df_adopt, use_container_width=True)

# ------------- Task 2 -------------
with tabs[1]:
    st.subheader("Sensitive Data Pasted into GenAI Tools")

    # Daily sensitive pastes
    df_daily = df_query(con, f"""
        WITH g AS (SELECT lower(domain) AS d FROM genai_domains)
        SELECT
          date_trunc('day', ts) AS day,
          lower(domain) AS genai_domain,
          sensitive_category,
          COUNT(*) AS events
        FROM clipboard_classification
        WHERE class='paste'
          AND lower(domain) IN (SELECT d FROM g)
          AND {date_filter}
        GROUP BY 1,2,3
        ORDER BY day, events DESC
    """)

    all_domains = sorted(df_daily.genai_domain.unique().tolist())
    sel_domains = st.multiselect("GenAI domains", options=all_domains, default=all_domains)
    df_daily_f = df_daily[df_daily.genai_domain.isin(sel_domains)]

    st.markdown("**Daily Sensitive Pastes by Category**")
    if not df_daily_f.empty:
        chart3 = alt.Chart(df_daily_f).mark_area().encode(
            x=alt.X("day:T", title="Day"),
            y=alt.Y("events:Q", stack='zero', title="Events"),
            color=alt.Color("sensitive_category:N", title="Category"),
            tooltip=["day:T", "genai_domain:N", "sensitive_category:N", "events:Q"]
        ).properties(height=350)
        st.altair_chart(chart3, use_container_width=True)
    else:
        st.info("No data for selected filters.")

    # Top categories
    df_top = df_query(con, f"""
        WITH g AS (SELECT lower(domain) AS d FROM genai_domains)
        SELECT
          lower(domain) AS genai_domain,
          sensitive_category,
          COUNT(*) AS events
        FROM clipboard_classification
        WHERE class='paste'
          AND lower(domain) IN (SELECT d FROM g)
          AND {date_filter}
        GROUP BY 1,2
        ORDER BY events DESC
        LIMIT 25
    """)
    st.markdown("**Top GenAI Targets & Categories**")
    st.dataframe(df_top, use_container_width=True)

    # NEW: Copy→Paste linkage evidence (source → destination)
    st.subheader("Copy → Paste Linkage (Evidence)")
    df_link = df_query(con, f"""
        SELECT
          date_trunc('day', paste_ts) AS day,
          COALESCE(clipboard_source_url_category, '(unknown)') AS source_category,
          lower(dest_domain) AS dest_domain,
          COUNT(*) AS events
        FROM clipboard_copy_paste_links
        WHERE {date_filter}
        GROUP BY 1,2,3
        ORDER BY day, events DESC
    """)

    # Heatmap by source_category vs dest_domain
    if not df_link.empty:
        st.markdown("**Heatmap: Source Category → Destination GenAI**")
        heat = alt.Chart(df_link).mark_rect().encode(
            x=alt.X("dest_domain:N", title="Destination Domain"),
            y=alt.Y("source_category:N", title="Source Category"),
            color=alt.Color("events:Q", title="Events", scale=alt.Scale(scheme="inferno")),
            tooltip=["day:T", "source_category:N", "dest_domain:N", "events:Q"]
        ).properties(height=320)
        st.altair_chart(heat, use_container_width=True)
    else:
        st.info("No copy→paste linkages found for the selected dates.")

    # Sample rows (masked)
    st.markdown("**Sample Linked Events (masked)**")
    df_link_samples = df_query(con, f"""
        SELECT
          paste_ts, user_id,
          lower(dest_domain) AS genai_domain,
          clipboard_source_url_category AS source_category,
          clipboard_source_hostname AS source_host
        FROM clipboard_copy_paste_links
        WHERE {date_filter}
        ORDER BY paste_ts DESC
        LIMIT 200
    """)
    st.dataframe(df_link_samples, use_container_width=True)

st.caption(f"DuckDB path: {DB_PATH}")