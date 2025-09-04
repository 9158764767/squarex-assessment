# src/run_analysis.py
"""
Run core SQL analysis and export charts to outputs/.
"""

import re
import duckdb, pandas as pd
import plotly.express as px
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "db" / "squarex.duckdb"
OUT = ROOT / "outputs"
OUT.mkdir(exist_ok=True, parents=True)

# --- re-register the UDF used inside the 'events_enriched' view ---
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
    # Accepts None and returns None if no match
    if not domain or not isinstance(domain, str):
        return None
    for pat, app in APP_MAP.items():
        if re.search(pat, domain, re.I):
            return app
    return None
# -----------------------------------------------------------------

def safe_write_image(fig, path_png):
    try:
        fig.write_image(path_png)
    except Exception as e:
        # Kaleido not installed or other image error — keep going with HTML only
        print(f"[WARN] Could not write PNG ({path_png}). Install 'kaleido' if you want static images. Details: {e}")

def main():
    con = duckdb.connect(DB_PATH)

    # IMPORTANT: allow NULLs to flow into/out of the UDF
    con.create_function(
        "infer_app_from_domain",
        infer_app_from_domain,
        ["VARCHAR"],
        "VARCHAR",
        null_handling="special"
    )

    # Top apps
    df_apps = con.execute("""
        WITH base AS (
          SELECT
            COALESCE(app_name, 'Unknown') AS app_name,
            user_id
          FROM events_enriched
        )
        SELECT app_name,
               COUNT(*) AS total_events,
               COUNT(DISTINCT user_id) AS unique_users
        FROM base
        GROUP BY 1
        ORDER BY unique_users DESC, total_events DESC
        LIMIT 25
    """).df()

    if not df_apps.empty:
        fig = px.bar(df_apps, x="app_name", y="unique_users", hover_data=["total_events"], title="Top Apps by Unique Users")
        fig.write_html(str(OUT / "top_apps.html"))
        safe_write_image(fig, str(OUT / "top_apps.png"))

    # Sensitive over time
    df_sens = con.execute("""
        SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
        FROM sensitive_events
        GROUP BY 1,2
        ORDER BY 1,2
    """).df()

    if not df_sens.empty:
        fig2 = px.line(df_sens, x="day", y="cnt", color="category", title="Sensitive Data Events Over Time")
        fig2.write_html(str(OUT / "sensitive_over_time.html"))
        safe_write_image(fig2, str(OUT / "sensitive_over_time.png"))

    # Risky destinations
    df_risky = con.execute("""
        SELECT app_name, domain, COUNT(*) AS events
        FROM events_enriched
        WHERE app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')
        GROUP BY 1,2
        ORDER BY events DESC
        LIMIT 50
    """).df()

    if not df_risky.empty:
        fig3 = px.bar(df_risky, x="domain", y="events", color="app_name", title="Top Risky Destinations")
        fig3.write_html(str(OUT / "risky_destinations.html"))
        safe_write_image(fig3, str(OUT / "risky_destinations.png"))

    print("[OK] Analysis complete. See outputs/ for charts.")

if __name__ == "__main__":
    main()
