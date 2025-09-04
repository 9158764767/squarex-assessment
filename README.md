# SquareX Data Analytics Assessment – Local (PyCharm) Project

This repo converts your Google Colab notebook into a clean, **local** project that runs in PyCharm (or any IDE).

## Quick Start

1. **Create & activate a virtual env**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   
   ```

2. **Install deps**
   ```bash
   pip install -r requirements.txt
   ```


3. **Open the dashboard (optional)**
   ```bash
   streamlit run dashboard_streamlit.py
   ```
   Then open the URL shown in the terminal.

## What’s Inside

- `src/prepare_db.py` → Scans `data/` and loads JSON into a local DuckDB at `db/squarex.duckdb`. Creates views for SaaS discovery and sensitive categories.
- `src/run_analysis.py` → Runs core SQL queries and saves Plotly charts to `outputs/`.
- `src/dashboard_streamlit.py` → One‑page executive dashboard (SaaS usage + Sensitive leakage).
- `src/classify_sensitive.py` → Heuristic/regex classifiers for PII, code, financial data, API keys, etc.
- `src/sql_queries.sql` → Reusable SQL used by the analysis and dashboard.

## Inputs: Expected Columns

The loader is flexible and tries to detect common field names. If your schema differs, update `prepare_db.py` mappings.

**Common fields:**
- `timestamp` (or `time`, `ts`)
- `user_id` (or `uid`, `employee`, `employee_id`)
- `url` (or `domain`, `host`)
- `app` (optional; inferred from domain when missing)
- `clipboard_text` (or `clipboard`, `text`, `content`) – used in Part 2

## Deliverables (to paste in your report)

- **Approach & decisions:** See inline comments in `prepare_db.py` and `classify_sensitive.py`.
- **SQL:** Check `src/sql_queries.sql`.
- **Screenshots/links:** Open Streamlit dashboard and take screenshots; static charts saved in `outputs/`.
- **Assumptions & limitations:** Documented in code comments and at the end of this README.

## Assumptions & Limitations (brief)

- Domain→App mapping is heuristic – improve `APP_MAP` in `prepare_db.py`.
- Sensitive classification is regex/heuristic first. You can add ML later.
- Clipboard content key name may vary; adjust `TEXT_FIELDS` in `prepare_db.py`.
- Timezone assumed to be local file timestamps; adjust as needed.

---

*Generated from your Colab notebook automatically, adapted for local use.*
