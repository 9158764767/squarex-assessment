# src/eda_outputs.py
from pathlib import Path
import duckdb
import pandas as pd
import plotly.express as px

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "db" / "squarex.duckdb"
OUT = ROOT / "outputs"
OUT.mkdir(parents=True, exist_ok=True)

def save(df: pd.DataFrame, name: str):
    p = OUT / f"{name}.csv"
    df.to_csv(p, index=False)
    return p

def write_fig(fig, name: str):
    html = OUT / f"{name}.html"
    fig.write_html(str(html))
    try:
        fig.write_image(str(OUT / f"{name}.png"))
    except Exception:
        pass
    return html

def main():
    con = duckdb.connect(DB_PATH)

    # Basic schema & counts
    schema_events = con.execute("DESCRIBE events").df()
    schema_sens   = con.execute("DESCRIBE sensitive_events").df()
    counts = con.execute("""
        SELECT
          (SELECT COUNT(*) FROM events) AS events,
          (SELECT COUNT(*) FROM sensitive_events) AS sensitive_events,
          (SELECT COUNT(DISTINCT user_id) FROM events) AS users,
          (SELECT COUNT(DISTINCT COALESCE(app, infer_app_from_domain(domain))) FROM events) AS apps
    """).df()

    save(schema_events, "eda_schema_events")
    save(schema_sens,   "eda_schema_sensitive_events")
    save(counts,        "eda_counts")

    # Nulls per column (events)
    nulls = con.execute("""
        SELECT column_name,
               SUM(nulls) AS nulls,
               SUM(rows) AS rows,
               100.0 * SUM(nulls) / NULLIF(SUM(rows),0) AS pct_nulls
        FROM (
          SELECT 'ts' AS column_name, COUNT(*) AS rows, SUM(CASE WHEN ts IS NULL THEN 1 ELSE 0 END) AS nulls FROM events UNION ALL
          SELECT 'user_id', COUNT(*), SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) FROM events UNION ALL
          SELECT 'url', COUNT(*), SUM(CASE WHEN url IS NULL THEN 1 ELSE 0 END) FROM events UNION ALL
          SELECT 'domain', COUNT(*), SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END) FROM events UNION ALL
          SELECT 'app', COUNT(*), SUM(CASE WHEN app IS NULL THEN 1 ELSE 0 END) FROM events UNION ALL
          SELECT 'clipboard_text', COUNT(*), SUM(CASE WHEN clipboard_text IS NULL THEN 1 ELSE 0 END) FROM events
        )
        GROUP BY 1 ORDER BY pct_nulls DESC
    """).df()
    save(nulls, "eda_nulls_events")

    # Top users, domains, apps
    top_users = con.execute("""
        SELECT user_id, COUNT(*) AS events
        FROM events_enriched
        GROUP BY 1 ORDER BY events DESC LIMIT 50
    """).df()
    top_domains = con.execute("""
        SELECT domain, COUNT(*) AS events
        FROM events_enriched
        GROUP BY 1 ORDER BY events DESC LIMIT 50
    """).df()
    top_apps = con.execute("""
        SELECT app_name, COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
        FROM events_enriched
        GROUP BY 1 ORDER BY users DESC, events DESC LIMIT 25
    """).df()

    save(top_users,   "eda_top_users")
    save(top_domains, "eda_top_domains")
    save(top_apps,    "eda_top_apps")

    if not top_apps.empty:
        fig = px.bar(top_apps, x="app_name", y="users", hover_data=["events"], title="EDA: Top Apps by Users")
        write_fig(fig, "eda_top_apps")

    # Hour-of-day heatmap (usage rhythm)
    hod = con.execute("""
        SELECT EXTRACT(hour FROM ts) AS hour, COUNT(*) AS events
        FROM events_enriched
        GROUP BY 1 ORDER BY 1
    """).df()
    save(hod, "eda_hour_of_day")
    if not hod.empty:
        fig = px.bar(hod, x="hour", y="events", title="EDA: Events by Hour")
        write_fig(fig, "eda_events_by_hour")

    # Sensitive category distribution
    sens_dist = con.execute("""
        SELECT category, COUNT(*) AS events
        FROM sensitive_events
        GROUP BY 1 ORDER BY events DESC
    """).df()
    save(sens_dist, "eda_sensitive_distribution")
    if not sens_dist.empty:
        fig = px.bar(sens_dist, x="category", y="events", title="EDA: Sensitive Category Distribution")
        write_fig(fig, "eda_sensitive_distribution")

    print("[OK] EDA outputs written to outputs/")

if __name__ == "__main__":
    main()
