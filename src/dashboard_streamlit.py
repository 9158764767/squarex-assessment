# # src/dashboard_streamlit.py
# import re
# import streamlit as st
# import duckdb
# import pandas as pd
# from pathlib import Path
#
# ROOT = Path(__file__).resolve().parents[1]
# DB_PATH = ROOT / "db" / "squarex.duckdb"
#
# st.set_page_config(page_title="SquareX Executive Dashboard", layout="wide")
# st.title("SquareX – SaaS Overview & Sensitive Data Leakage")
#
# # ---- UDF (same logic as in prepare_db/run_analysis) ----
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
# def infer_app_from_domain(domain: str):
#     if not domain or not isinstance(domain, str):
#         return None
#     for pat, app in APP_MAP.items():
#         if re.search(pat, domain, re.I):
#             return app
#     return None
# # ---------------------------------------------------------
#
# con = duckdb.connect(DB_PATH)
#
# # Register UDF so views that reference it can run
# con.create_function(
#     "infer_app_from_domain",
#     infer_app_from_domain,
#     ["VARCHAR"],
#     "VARCHAR",
#     null_handling="special",
# )
#
# # Prefer materialized table if present (no UDF dependency), else view
# def has_table(name: str) -> bool:
#     q = """
#       SELECT 1
#       FROM information_schema.tables
#       WHERE table_schema IN ('main','memory')
#         AND table_name = ?
#       LIMIT 1
#     """
#     return con.execute(q, [name]).fetchone() is not None
#
# SRC = "events_enriched_mat" if has_table("events_enriched_mat") else "events_enriched"
#
# # ---- Filters ----
# users_df = con.execute(
#     f"SELECT DISTINCT user_id FROM {SRC} WHERE user_id IS NOT NULL ORDER BY 1"
# ).df()
# apps_df = con.execute(
#     f"SELECT DISTINCT app_name FROM {SRC} WHERE app_name IS NOT NULL ORDER BY 1"
# ).df()
#
# users = users_df["user_id"].tolist() if not users_df.empty else []
# apps = apps_df["app_name"].tolist() if not apps_df.empty else []
#
# c1, c2 = st.columns(2)
# with c1:
#     sel_users = st.multiselect("Filter by users", users, default=users[:10] if users else [])
# with c2:
#     sel_apps = st.multiselect("Filter by apps", apps, default=apps[:10] if apps else [])
#
# user_filter = ""
# if sel_users:
#     quoted_users = ",".join([f"'{u}'" for u in sel_users])
#     user_filter = f"AND user_id IN ({quoted_users})"
#
# app_filter = ""
# if sel_apps:
#     quoted_apps = ",".join([f"'{a}'" for a in sel_apps])
#     app_filter = f"AND app_name IN ({quoted_apps})"
#
# # ---- KPIs ----
# kpi = con.execute(f"""
#     SELECT
#       COUNT(*) AS events,
#       COUNT(DISTINCT user_id) AS users,
#       COUNT(DISTINCT app_name) AS apps
#     FROM {SRC}
#     WHERE 1=1 {user_filter} {app_filter}
# """).df()
# if not kpi.empty:
#     krow = kpi.iloc[0]
# else:
#     krow = {"events": 0, "users": 0, "apps": 0}
#
# k1, k2, k3 = st.columns(3)
# k1.metric("Total Events", int(krow["events"]))
# k2.metric("Active Users", int(krow["users"]))
# k3.metric("Apps Seen", int(krow["apps"]))
#
# st.markdown("---")
#
# # ---- Top apps ----
# df_apps = con.execute(f"""
#     SELECT app_name, COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
#     FROM {SRC}
#     WHERE app_name IS NOT NULL {user_filter} {app_filter}
#     GROUP BY 1
#     ORDER BY users DESC, events DESC
#     LIMIT 25
# """).df()
# st.subheader("Top Apps by Users")
# if not df_apps.empty:
#     st.bar_chart(df_apps.set_index("app_name")["users"])
# else:
#     st.info("No data available for the selected filters.")
#
# # ---- Sensitive over time ----
# df_sens = con.execute("""
#     SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
#     FROM sensitive_events
#     GROUP BY 1,2
#     ORDER BY 1,2
# """).df()
# st.subheader("Sensitive Data Events Over Time")
# if not df_sens.empty:
#     df_pivot = df_sens.pivot_table(index="day", columns="category", values="cnt", aggfunc="sum").fillna(0)
#     st.line_chart(df_pivot)
# else:
#     st.info("No sensitive events detected yet. Add data or adjust classifiers.")
#
# # ---- Risky destinations ----
# df_risky = con.execute(f"""
#     SELECT app_name, domain, COUNT(*) AS events
#     FROM {SRC}
#     WHERE app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')
#       {user_filter} {app_filter}
#     GROUP BY 1,2
#     ORDER BY events DESC
#     LIMIT 100
# """).df()
# st.subheader("Top Risky Destinations (GenAI & Cloud Storage)")
# st.dataframe(df_risky)
#
# st.markdown("---")
# st.caption("Notes: heuristic app inference from domain; regex-based sensitive classification. "
#            "To avoid UDFs at runtime, materialize with `events_enriched_mat` in prepare_db.py.")

# =============================================================================

#
# # src/dashboard_streamlit.py
# import re
# import duckdb
# import pandas as pd
# import plotly.express as px
# import streamlit as st
# from pathlib import Path
#
# st.set_page_config(page_title="SquareX – SaaS & Sensitive Leakage", layout="wide")
# st.title("SquareX – SaaS Overview & Sensitive Data Leakage")
#
# ROOT = Path(__file__).resolve().parents[1]
# DB_PATH = ROOT / "db" / "squarex.duckdb"
#
# # ---------- UDF (same as in prepare_db/run_analysis) ----------
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
# def infer_app_from_domain(domain: str):
#     if not domain or not isinstance(domain, str):
#         return None
#     for pat, app in APP_MAP.items():
#         if re.search(pat, domain, re.I):
#             return app
#     return None
# # --------------------------------------------------------------
#
# @st.cache_resource(show_spinner=False)
# def get_con():
#     con = duckdb.connect(DB_PATH)
#     con.create_function(
#         "infer_app_from_domain",
#         infer_app_from_domain,
#         ["VARCHAR"],
#         "VARCHAR",
#         null_handling="special",
#     )
#     return con
#
# con = get_con()
#
# def has_table(name: str) -> bool:
#     q = """
#       SELECT 1
#       FROM information_schema.tables
#       WHERE table_schema IN ('main','memory')
#         AND table_name = ?
#       LIMIT 1
#     """
#     return con.execute(q, [name]).fetchone() is not None
#
# SRC = "events_enriched_mat" if has_table("events_enriched_mat") else "events_enriched"
#
# # ---------- Sidebar Filters ----------
# st.sidebar.header("Filters")
# users_df = con.execute(f"SELECT DISTINCT user_id FROM {SRC} WHERE user_id IS NOT NULL ORDER BY 1").df()
# apps_df  = con.execute(f"SELECT DISTINCT app_name FROM {SRC} WHERE app_name IS NOT NULL ORDER BY 1").df()
# users = users_df["user_id"].tolist() if not users_df.empty else []
# apps  = apps_df["app_name"].tolist() if not apps_df.empty else []
#
# sel_users = st.sidebar.multiselect("Users", users, default=users[:10] if users else [])
# sel_apps  = st.sidebar.multiselect("Apps",  apps,  default=apps[:10]  if apps  else [])
#
# user_filter = ""
# if sel_users:
#     quoted = ",".join([f"'{u}'" for u in sel_users])
#     user_filter = f" AND user_id IN ({quoted}) "
#
# app_filter = ""
# if sel_apps:
#     quoted = ",".join([f"'{a}'" for a in sel_apps])
#     app_filter = f" AND app_name IN ({quoted}) "
#
# # ---------- Helper: apply filters to base query on {SRC} ----------
# def q_base(where_extra: str = ""):
#     return f"FROM {SRC} WHERE 1=1 {user_filter} {app_filter} {where_extra}"
#
# # ---------- Tabs ----------
# tab_overview, tab_eda, tab_t1, tab_t2, tab_examples, tab_queries = st.tabs(
#     ["Overview", "EDA", "Task-1: SaaS Discovery", "Task-2: Sensitive Leakage", "Examples", "Queries (SQL + Results)"]
# )
#
# # ===== Overview =====
# with tab_overview:
#     kpi = con.execute(f"""
#         SELECT
#           (SELECT COUNT(*) {q_base()}) AS events,
#           (SELECT COUNT(DISTINCT user_id) {q_base()}) AS users,
#           (SELECT COUNT(DISTINCT app_name) {q_base()}) AS apps
#     """).df().iloc[0]
#
#     c1, c2, c3 = st.columns(3)
#     c1.metric("Total Events", int(kpi["events"]))
#     c2.metric("Active Users", int(kpi["users"]))
#     c3.metric("Apps Seen", int(kpi["apps"]))
#
#     st.markdown("---")
#     top_apps = con.execute(f"""
#         SELECT app_name, COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
#         {q_base(" AND app_name IS NOT NULL")}
#         GROUP BY 1 ORDER BY users DESC, events DESC LIMIT 25
#     """).df()
#     st.subheader("Top Apps by Users")
#     if not top_apps.empty:
#         st.plotly_chart(px.bar(top_apps, x="app_name", y="users",
#                                hover_data=["events"], title="Top Apps by Users"), use_container_width=True)
#     else:
#         st.info("No data for current filters.")
#
#     st.markdown("---")
#     risky = con.execute(f"""
#         SELECT app_name, domain, COUNT(*) AS events
#         {q_base(" AND app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')")}
#         GROUP BY 1,2 ORDER BY events DESC LIMIT 100
#     """).df()
#     st.subheader("Top Risky Destinations (GenAI & Cloud Storage)")
#     st.dataframe(risky, use_container_width=True)
#
# # ===== EDA =====
# with tab_eda:
#     st.subheader("Basic Counts")
#     counts = con.execute(f"""
#         SELECT
#           (SELECT COUNT(*) {q_base()}) AS events,
#           (SELECT COUNT(DISTINCT user_id) {q_base()}) AS users,
#           (SELECT COUNT(DISTINCT app_name) {q_base()}) AS apps,
#           (SELECT COUNT(*) FROM sensitive_events) AS sensitive_events
#     """).df()
#     st.dataframe(counts)
#
#     c1, c2 = st.columns(2)
#     with c1:
#         st.markdown("**Schema: events**")
#         st.dataframe(con.execute("DESCRIBE events").df(), use_container_width=True)
#     with c2:
#         st.markdown("**Schema: sensitive_events**")
#         st.dataframe(con.execute("DESCRIBE sensitive_events").df(), use_container_width=True)
#
#     st.markdown("---")
#     nulls = con.execute(f"""
#         SELECT column_name, SUM(nulls) AS nulls, SUM(rows) AS rows,
#                100.0 * SUM(nulls) / NULLIF(SUM(rows),0) AS pct_nulls
#         FROM (
#           SELECT 'ts' AS column_name, COUNT(*) AS rows, SUM(CASE WHEN ts IS NULL THEN 1 ELSE 0 END) AS nulls {q_base()} UNION ALL
#           SELECT 'user_id', COUNT(*), SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
#           SELECT 'url', COUNT(*), SUM(CASE WHEN url IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
#           SELECT 'domain', COUNT(*), SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
#           SELECT 'app_name', COUNT(*), SUM(CASE WHEN app_name IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
#           SELECT 'clipboard_text', COUNT(*), SUM(CASE WHEN clipboard_text IS NULL THEN 1 ELSE 0 END) {q_base()}
#         )
#         GROUP BY 1 ORDER BY pct_nulls DESC
#     """).df()
#     st.subheader("Nulls per Column")
#     st.dataframe(nulls, use_container_width=True)
#
#     st.markdown("---")
#     hod = con.execute(f"""
#         SELECT EXTRACT(hour FROM ts) AS hour, COUNT(*) AS events
#         {q_base()}
#         GROUP BY 1 ORDER BY 1
#     """).df()
#     st.subheader("Events by Hour of Day")
#     if not hod.empty:
#         st.plotly_chart(px.bar(hod, x="hour", y="events", title="Events by Hour"), use_container_width=True)
#     else:
#         st.info("No events for current filters.")
#
# # ===== Task-1: SaaS Discovery =====
# with tab_t1:
#     daily = con.execute(f"""
#         SELECT date_trunc('day', ts) AS day, app_name,
#                COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
#         {q_base()}
#         GROUP BY 1,2 ORDER BY 1,2
#     """).df()
#     st.subheader("Daily Users per App")
#     if not daily.empty:
#         st.plotly_chart(px.line(daily, x="day", y="users", color="app_name",
#                                 title="Daily Users per App"), use_container_width=True)
#     else:
#         st.info("No data for current filters.")
#
#     user_app = con.execute(f"""
#         SELECT user_id, app_name, COUNT(*) AS events
#         {q_base()}
#         GROUP BY 1,2
#     """).df()
#     st.subheader("User ↔ App Matrix (Events)")
#     st.dataframe(user_app, use_container_width=True, height=300)
#
#     # Risk scores (ensure weight table exists)
#     con.execute("""
#         CREATE TABLE IF NOT EXISTS app_risk_weight(app_name VARCHAR, weight DOUBLE);
#     """)
#     # Replace the old weight-table logic with this:
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
#     risk = con.execute(f"""
#         WITH base AS (
#           SELECT user_id, app_name, COUNT(*) AS events
#           {q_base()}
#           GROUP BY 1,2
#         )
#         SELECT b.app_name,
#                SUM(b.events * COALESCE(w.weight,1.0)) AS risk_score,
#                SUM(b.events) AS events,
#                COUNT(DISTINCT b.user_id) AS users
#         FROM base b
#         LEFT JOIN app_risk_weight w USING(app_name)
#         GROUP BY 1
#         ORDER BY risk_score DESC
#     """).df()
#     st.subheader("App Risk Scores")
#     if not risk.empty:
#         st.plotly_chart(px.bar(risk, x="app_name", y="risk_score",
#                                hover_data=["events","users"], title="Risk Scores"),
#                         use_container_width=True)
#     else:
#         st.info("No data for risk scoring with current filters.")
#
# # ===== Task-2: Sensitive Leakage =====
# with tab_t2:
#     sens_time = con.execute("""
#         SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
#         FROM sensitive_events
#         GROUP BY 1,2 ORDER BY 1,2
#     """).df()
#     st.subheader("Sensitive Categories Over Time")
#     if not sens_time.empty:
#         st.plotly_chart(px.line(sens_time, x="day", y="cnt", color="category",
#                                 title="Sensitive Over Time"), use_container_width=True)
#     else:
#         st.info("No sensitive events detected.")
#
#     sens_app = con.execute("""
#         SELECT COALESCE(app_name,'Unknown') AS app_name, category, COUNT(*) AS events
#         FROM sensitive_events
#         GROUP BY 1,2 ORDER BY events DESC
#     """).df()
#     st.subheader("Sensitive by App (Stacked)")
#     if not sens_app.empty:
#         st.plotly_chart(px.bar(sens_app, x="app_name", y="events", color="category",
#                                title="Sensitive by App", barmode="stack"),
#                         use_container_width=True)
#     else:
#         st.info("No sensitive-by-app data available.")
#
#     sens_user = con.execute("""
#         SELECT user_id, category, COUNT(*) AS events
#         FROM sensitive_events
#         GROUP BY 1,2 ORDER BY events DESC
#     """).df()
#     st.subheader("Sensitive by User")
#     st.dataframe(sens_user, use_container_width=True, height=300)
#
#     risky = con.execute(f"""
#         SELECT app_name, domain, COUNT(*) AS events
#         {q_base(" AND app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')")}
#         GROUP BY 1,2 ORDER BY events DESC LIMIT 200
#     """).df()
#     st.subheader("Top Risky Destinations (GenAI & Cloud)")
#     st.dataframe(risky, use_container_width=True, height=300)
#
# # ===== Examples =====
# with tab_examples:
#     examples = con.execute(f"""
#         SELECT date_trunc('minute', e.ts) AS ts_minute,
#                e.user_id,
#                e.app_name,
#                s.category,
#                e.domain,
#                LEFT(e.clipboard_text, 180) AS sample_clipboard
#         FROM {SRC} e
#         JOIN sensitive_events s USING (ts, user_id, domain, app_name)
#         WHERE e.clipboard_text IS NOT NULL
#         ORDER BY ts_minute DESC
#         LIMIT 200
#     """).df()
#     st.subheader("Sensitive Examples (Truncated)")
#     st.dataframe(examples, use_container_width=True, height=450)
#
# st.caption("Notes: Heuristic domain→app mapping; regex-based sensitive classification. "
#            "Materialize with 'events_enriched_mat' in prepare_db.py to avoid UDF dependencies.")

# ========================================================================================================


# src/dashboard_streamlit.py
import re
from textwrap import dedent
from pathlib import Path

import duckdb
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="SquareX – SaaS & Sensitive Leakage", layout="wide")
st.title("SquareX – SaaS Overview & Sensitive Data Leakage")

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "db" / "squarex.duckdb"
SQL_FILE = ROOT / "src" / "sql_queries.sql"

# ---------- UDF (same logic as in prepare_db/run_analysis) ----------
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
def infer_app_from_domain(domain: str):
    if not domain or not isinstance(domain, str):
        return None
    for pat, app in APP_MAP.items():
        if re.search(pat, domain, re.I):
            return app
    return None
# --------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def get_con():
    con = duckdb.connect(DB_PATH)
    con.create_function(
        "infer_app_from_domain",
        infer_app_from_domain,
        ["VARCHAR"],
        "VARCHAR",
        null_handling="special",
    )
    return con

con = get_con()

def has_table(name: str) -> bool:
    q = """
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema IN ('main','memory')
        AND table_name = ?
      LIMIT 1
    """
    return con.execute(q, [name]).fetchone() is not None

# Prefer materialized table if available
SRC = "events_enriched_mat" if has_table("events_enriched_mat") else "events_enriched"

# ---------- Sidebar Filters ----------
st.sidebar.header("Filters")

users_df = con.execute(f"SELECT DISTINCT user_id FROM {SRC} WHERE user_id IS NOT NULL ORDER BY 1").df()
apps_df  = con.execute(f"SELECT DISTINCT app_name FROM {SRC} WHERE app_name IS NOT NULL ORDER BY 1").df()
users = users_df["user_id"].tolist() if not users_df.empty else []
apps  = apps_df["app_name"].tolist() if not apps_df.empty else []

sel_users = st.sidebar.multiselect("Users", users, default=users[:10] if users else [])
sel_apps  = st.sidebar.multiselect("Apps",  apps,  default=apps[:10]  if apps  else [])

user_filter = ""
if sel_users:
    quoted_users = ",".join([f"'{u}'" for u in sel_users])
    user_filter = f" AND user_id IN ({quoted_users}) "

app_filter = ""
if sel_apps:
    quoted_apps = ",".join([f"'{a}'" for a in sel_apps])
    app_filter = f" AND app_name IN ({quoted_apps}) "

def q_base(where_extra: str = ""):
    """Base FROM/WHERE with sidebar filters applied."""
    return f"FROM {SRC} WHERE 1=1 {user_filter} {app_filter} {where_extra}"

# ---------- Helpers for Queries Tab ----------
def load_sql_sections(sql_text: str):
    """
    Split the SQL pack into labeled statements by headers like:
    -- EDA_00: Basic counts
    Returns list of dicts: {key, title, sql}
    """
    sections = []
    current_key, current_title, current_sql = None, None, []
    for line in sql_text.splitlines():
        if line.strip().startswith("--") and ":" in line and "_" in line[:12]:
            # Flush previous section
            if current_key and current_sql:
                sections.append({
                    "key": current_key,
                    "title": current_title,
                    "sql": dedent("\n".join(current_sql)).strip()
                })
            header = line.strip()[2:].strip()
            try:
                key, title = header.split(":", 1)
                current_key = key.strip()
                current_title = title.strip()
                current_sql = []
            except ValueError:
                pass
        else:
            if current_key is not None:
                current_sql.append(line)
    if current_key and current_sql:
        sections.append({
            "key": current_key,
            "title": current_title,
            "sql": dedent("\n".join(current_sql)).strip()
        })
    return sections

def substitute_src(sql: str, src_table: str):
    return sql.replace("{SRC}", src_table)

def run_and_show(con_, sql: str, title: str, try_chart: bool = True):
    df = con_.execute(sql).df()
    st.markdown(f"**{title}**")
    st.code(sql, language="sql")
    st.dataframe(df, use_container_width=True)
    if not df.empty:
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"{title.lower().replace(' ','_')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    if try_chart and not df.empty and {"day", "users"}.issubset(df.columns):
        color_col = None
        # pick a color column if more than 2 columns exist
        for c in df.columns:
            if c not in ("day", "users"):
                color_col = c
                break
        st.plotly_chart(
            px.line(df, x="day", y="users", color=color_col, title=f"{title} (chart)"),
            use_container_width=True
        )

# ---------- Tabs ----------
tab_overview, tab_eda, tab_t1, tab_t2, tab_examples, tab_queries = st.tabs(
    ["Overview", "EDA", "Task-1: SaaS Discovery", "Task-2: Sensitive Leakage", "Examples", "Queries (SQL + Results)"]
)

# ===== Overview =====
with tab_overview:
    kpi = con.execute(f"""
        SELECT
          (SELECT COUNT(*) {q_base()}) AS events,
          (SELECT COUNT(DISTINCT user_id) {q_base()}) AS users,
          (SELECT COUNT(DISTINCT app_name) {q_base()}) AS apps
    """).df().iloc[0]

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Events", int(kpi["events"]))
    c2.metric("Active Users", int(kpi["users"]))
    c3.metric("Apps Seen", int(kpi["apps"]))

    st.markdown("---")
    top_apps = con.execute(f"""
        SELECT app_name, COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
        {q_base(" AND app_name IS NOT NULL")}
        GROUP BY 1 ORDER BY users DESC, events DESC LIMIT 25
    """).df()
    st.subheader("Top Apps by Users")
    if not top_apps.empty:
        st.plotly_chart(
            px.bar(top_apps, x="app_name", y="users", hover_data=["events"], title="Top Apps by Users"),
            use_container_width=True
        )
    else:
        st.info("No data for current filters.")

    st.markdown("---")
    risky = con.execute(f"""
        SELECT app_name, domain, COUNT(*) AS events
        {q_base(" AND app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')")}
        GROUP BY 1,2 ORDER BY events DESC LIMIT 100
    """).df()
    st.subheader("Top Risky Destinations (GenAI & Cloud Storage)")
    st.dataframe(risky, use_container_width=True)

# ===== EDA =====
with tab_eda:
    st.subheader("Basic Counts")
    counts = con.execute(f"""
        SELECT
          (SELECT COUNT(*) {q_base()}) AS events,
          (SELECT COUNT(DISTINCT user_id) {q_base()}) AS users,
          (SELECT COUNT(DISTINCT app_name) {q_base()}) AS apps,
          (SELECT COUNT(*) FROM sensitive_events) AS sensitive_events
    """).df()
    st.dataframe(counts, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Schema: events**")
        st.dataframe(con.execute("DESCRIBE events").df(), use_container_width=True)
    with c2:
        st.markdown("**Schema: sensitive_events**")
        st.dataframe(con.execute("DESCRIBE sensitive_events").df(), use_container_width=True)

    st.markdown("---")
    nulls = con.execute(f"""
        SELECT column_name, SUM(nulls) AS nulls, SUM(rows) AS rows,
               100.0 * SUM(nulls) / NULLIF(SUM(rows),0) AS pct_nulls
        FROM (
          SELECT 'ts' AS column_name, COUNT(*) AS rows, SUM(CASE WHEN ts IS NULL THEN 1 ELSE 0 END) AS nulls {q_base()} UNION ALL
          SELECT 'user_id', COUNT(*), SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
          SELECT 'url', COUNT(*), SUM(CASE WHEN url IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
          SELECT 'domain', COUNT(*), SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
          SELECT 'app_name', COUNT(*), SUM(CASE WHEN app_name IS NULL THEN 1 ELSE 0 END) {q_base()} UNION ALL
          SELECT 'clipboard_text', COUNT(*), SUM(CASE WHEN clipboard_text IS NULL THEN 1 ELSE 0 END) {q_base()}
        )
        GROUP BY 1 ORDER BY pct_nulls DESC
    """).df()
    st.subheader("Nulls per Column")
    st.dataframe(nulls, use_container_width=True)

    st.markdown("---")
    hod = con.execute(f"""
        SELECT EXTRACT(hour FROM ts) AS hour, COUNT(*) AS events
        {q_base()}
        GROUP BY 1 ORDER BY 1
    """).df()
    st.subheader("Events by Hour of Day")
    if not hod.empty:
        st.plotly_chart(px.bar(hod, x="hour", y="events", title="Events by Hour"), use_container_width=True)
    else:
        st.info("No events for current filters.")

# ===== Task-1: SaaS Discovery =====
with tab_t1:
    daily = con.execute(f"""
        SELECT date_trunc('day', ts) AS day, app_name,
               COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
        {q_base()}
        GROUP BY 1,2 ORDER BY 1,2
    """).df()
    st.subheader("Daily Users per App")
    if not daily.empty:
        st.plotly_chart(px.line(daily, x="day", y="users", color="app_name",
                                title="Daily Users per App"), use_container_width=True)
    else:
        st.info("No data for current filters.")

    user_app = con.execute(f"""
        SELECT user_id, app_name, COUNT(*) AS events
        {q_base()}
        GROUP BY 1,2
    """).df()
    st.subheader("User ↔ App Matrix (Events)")
    st.dataframe(user_app, use_container_width=True, height=300)

    # Recreate the app risk weight table each run (no ON CONFLICT)
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

    risk = con.execute(f"""
        WITH base AS (
          SELECT user_id, app_name, COUNT(*) AS events
          {q_base()}
          GROUP BY 1,2
        )
        SELECT b.app_name,
               SUM(b.events * COALESCE(w.weight,1.0)) AS risk_score,
               SUM(b.events) AS events,
               COUNT(DISTINCT b.user_id) AS users
        FROM base b
        LEFT JOIN app_risk_weight w USING(app_name)
        GROUP BY 1
        ORDER BY risk_score DESC
    """).df()
    st.subheader("App Risk Scores")
    if not risk.empty:
        st.plotly_chart(px.bar(risk, x="app_name", y="risk_score",
                               hover_data=["events", "users"], title="Risk Scores"),
                        use_container_width=True)
    else:
        st.info("No data for risk scoring with current filters.")

# ===== Task-2: Sensitive Leakage =====
with tab_t2:
    sens_time = con.execute("""
        SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY 1,2
    """).df()
    st.subheader("Sensitive Categories Over Time")
    if not sens_time.empty:
        st.plotly_chart(px.line(sens_time, x="day", y="cnt", color="category",
                                title="Sensitive Over Time"), use_container_width=True)
    else:
        st.info("No sensitive events detected.")

    sens_app = con.execute("""
        SELECT COALESCE(app_name,'Unknown') AS app_name, category, COUNT(*) AS events
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY events DESC
    """).df()
    st.subheader("Sensitive by App (Stacked)")
    if not sens_app.empty:
        st.plotly_chart(px.bar(sens_app, x="app_name", y="events", color="category",
                               title="Sensitive by App", barmode="stack"),
                        use_container_width=True)
    else:
        st.info("No sensitive-by-app data available.")

    sens_user = con.execute("""
        SELECT user_id, category, COUNT(*) AS events
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY events DESC
    """).df()
    st.subheader("Sensitive by User")
    st.dataframe(sens_user, use_container_width=True, height=300)

    risky = con.execute(f"""
        SELECT app_name, domain, COUNT(*) AS events
        {q_base(" AND app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')")}
        GROUP BY 1,2 ORDER BY events DESC LIMIT 200
    """).df()
    st.subheader("Top Risky Destinations (GenAI & Cloud)")
    st.dataframe(risky, use_container_width=True, height=300)

# ===== Examples =====
with tab_examples:
    examples = con.execute(f"""
        SELECT date_trunc('minute', e.ts) AS ts_minute,
               e.user_id,
               e.app_name,
               s.category,
               e.domain,
               LEFT(e.clipboard_text, 180) AS sample_clipboard
        FROM {SRC} e
        JOIN sensitive_events s USING (ts, user_id, domain, app_name)
        WHERE e.clipboard_text IS NOT NULL
        ORDER BY ts_minute DESC
        LIMIT 200
    """).df()
    st.subheader("Sensitive Examples (Truncated)")
    st.dataframe(examples, use_container_width=True, height=450)

# ===== Queries (SQL + Results) =====
with tab_queries:
    st.subheader("SQL Pack — Run & Export")

    # Quick sanity: do we have sensitive events?
    sens_cnt = con.execute("SELECT COUNT(*) AS n FROM sensitive_events").df()["n"].iloc[0]
    c = st.container()
    c.metric("Sensitive events rows", int(sens_cnt))

    if not SQL_FILE.exists():
        st.warning("`src/sql_queries.sql` not found.")
    else:
        raw = SQL_FILE.read_text(encoding="utf-8")
        sections = load_sql_sections(raw)

        # --- Build groups, but keep a flat list fallback ---
        group_map = {"EDA": [], "T1": [], "T2": []}
        for s in sections:
            key = s["key"]
            if   key.upper().startswith("EDA_"): group_map["EDA"].append(s)
            elif key.upper().startswith("T1_"):  group_map["T1"].append(s)
            elif key.upper().startswith("T2_"):  group_map["T2"].append(s)

        # Label with counts; always include All
        options = [
            f"EDA ({len(group_map['EDA'])})",
            f"Task-1 (SaaS Discovery) ({len(group_map['T1'])})",
            f"Task-2 (Sensitive Leakage) ({len(group_map['T2'])})",
            f"All ({len(sections)})"
        ]
        choice = st.selectbox("Select query group", options, index=3)  # default to All

        # Decide which list to render
        if choice.startswith("EDA"):
            to_render = group_map["EDA"]
        elif choice.startswith("Task-1"):
            to_render = group_map["T1"]
        elif choice.startswith("Task-2"):
            to_render = group_map["T2"]
        else:
            to_render = sections  # All

        # If a group is empty, say it explicitly
        if not to_render:
            st.info("No queries found for this group. Choose **All** to see every query.")
        else:
            for sec in to_render:
                sql_stmt = substitute_src(sec["sql"], SRC)
                with st.expander(f"{sec['key']} — {sec['title']}", expanded=False):
                    run_and_show(con, sql_stmt, f"{sec['key']} — {sec['title']}")

st.caption(
    "Notes: heuristic domain→app mapping; regex-based sensitive classification. "
    "Materialize with 'events_enriched_mat' in prepare_db.py to avoid UDF dependencies."
)

# --- Ensure DB dir exists and build DB on first run (Streamlit Cloud safe) ---
from prepare_db import main as build_db
DB_PATH.parent.mkdir(parents=True, exist_ok=True)  # make ./db/ if missing
try:
    # If DB file is missing, build it from data/
    if not DB_PATH.exists():
        import streamlit as st
        st.info("Initializing database from data/…")
        build_db()
except Exception as e:
    # Provide a friendly error if data/ is empty or something else goes wrong
    import streamlit as st
    st.error(f"Database initialization failed: {e}")
# ----------------------------------------------------------------------------- 

