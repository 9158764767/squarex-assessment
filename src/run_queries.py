# src/run_queries.py
from pathlib import Path
import duckdb, pandas as pd
import plotly.express as px

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "db" / "squarex.duckdb"
OUT = ROOT / "outputs"
OUT.mkdir(parents=True, exist_ok=True)

def save(df, name):
    p = OUT / f"{name}.csv"
    df.to_csv(p, index=False); return p

def write(fig, name):
    html = OUT / f"{name}.html"
    fig.write_html(str(html))
    try:
        fig.write_image(str(OUT / f"{name}.png"))
    except Exception:
        pass
    return html

def main():
    con = duckdb.connect(DB_PATH)

    # ---------- TASK 1: SaaS Discovery ----------
    # 1) Top SaaS by unique users and events
    q_top_apps = """
        SELECT app_name,
               COUNT(*) AS total_events,
               COUNT(DISTINCT user_id) AS unique_users
        FROM events_enriched
        GROUP BY 1
        ORDER BY unique_users DESC, total_events DESC
        LIMIT 50
    """
    top_apps = con.execute(q_top_apps).df(); save(top_apps, "q1_top_apps")
    if not top_apps.empty:
        write(px.bar(top_apps, x="app_name", y="unique_users",
                     hover_data=["total_events"], title="Top Apps by Users"),
              "q1_top_apps")

    # 2) Daily app usage
    q_daily_app = """
        SELECT date_trunc('day', ts) AS day, app_name,
               COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
        FROM events_enriched
        GROUP BY 1,2 ORDER BY 1,2
    """
    daily_app = con.execute(q_daily_app).df(); save(daily_app, "q1_daily_app_usage")
    if not daily_app.empty:
        write(px.line(daily_app, x="day", y="users", color="app_name",
                      title="Daily Users per App"), "q1_daily_app_usage")

    # 3) User ↔ App matrix (breadth of adoption)
    q_user_app = """
        SELECT user_id, app_name, COUNT(*) AS events
        FROM events_enriched
        GROUP BY 1,2
    """
    user_app = con.execute(q_user_app).df(); save(user_app, "q1_user_app_matrix")

    # 4) Risk scoring (GenAI/Cloud higher)
    con.execute("""
        CREATE OR REPLACE TABLE app_risk_weight(app_name VARCHAR, weight DOUBLE);
    """)
    # Replace the previous CREATE TABLE / INSERT ... ON CONFLICT block with:
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

    q_risk = """
        WITH base AS (
          SELECT e.user_id, e.app_name, COUNT(*) AS events
          FROM events_enriched e
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
    """
    risk = con.execute(q_risk).df(); save(risk, "q1_app_risk_scores")
    if not risk.empty:
        write(px.bar(risk, x="app_name", y="risk_score",
                     hover_data=["events","users"], title="App Risk Scores"),
              "q1_app_risk_scores")

    # ---------- TASK 2: Sensitive Leakage ----------
    # 5) Sensitive categories over time
    q_sens_time = """
        SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY 1,2
    """
    sens_time = con.execute(q_sens_time).df(); save(sens_time, "q2_sensitive_over_time")
    if not sens_time.empty:
        write(px.line(sens_time, x="day", y="cnt", color="category",
                      title="Sensitive Categories Over Time"),
              "q2_sensitive_over_time")

    # 6) Sensitive by app
    q_sens_app = """
        SELECT COALESCE(app_name,'Unknown') AS app_name, category, COUNT(*) AS events
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY events DESC
    """
    sens_app = con.execute(q_sens_app).df(); save(sens_app, "q2_sensitive_by_app")

    # 7) Sensitive by user
    q_sens_user = """
        SELECT user_id, category, COUNT(*) AS events
        FROM sensitive_events
        GROUP BY 1,2 ORDER BY events DESC
    """
    sens_user = con.execute(q_sens_user).df(); save(sens_user, "q2_sensitive_by_user")

    # 8) Top risky destinations (GenAI & Cloud)
    q_risky_dest = """
        SELECT app_name, domain, COUNT(*) AS events
        FROM events_enriched
        WHERE app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')
        GROUP BY 1,2 ORDER BY events DESC LIMIT 200
    """
    risky_dest = con.execute(q_risky_dest).df(); save(risky_dest, "q2_risky_destinations")

    # 9) “Examples” table: sampled sensitive snippets per app/category (for screenshots)
    q_examples = """
        SELECT
          date_trunc('minute', e.ts) AS ts_minute,
          e.user_id,
          e.app_name,
          s.category,
          e.domain,
          LEFT(e.clipboard_text, 180) AS sample_clipboard
        FROM events_enriched e
        JOIN sensitive_events s USING (ts, user_id, domain, app_name)
        WHERE e.clipboard_text IS NOT NULL
        ORDER BY ts_minute DESC
        LIMIT 200
    """
    examples = con.execute(q_examples).df(); save(examples, "q2_sensitive_examples")

    print("[OK] All query outputs written to outputs/")

if __name__ == "__main__":
    main()
