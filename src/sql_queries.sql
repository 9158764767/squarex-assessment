-- =========================================================
-- SquareX Assessment – Canonical SQL Pack (DuckDB)
-- Covers: EDA, Task-1 (SaaS Discovery), Task-2 (Sensitive Leakage)
-- NOTE: Replace {SRC} with either events_enriched_mat (preferred)
--       or events_enriched if you didn't materialize the view.
-- =========================================================

-- ============ EDA ============

-- EDA_00: Basic counts
SELECT
  (SELECT COUNT(*) FROM {SRC})                                  AS events,
  (SELECT COUNT(DISTINCT user_id) FROM {SRC})                   AS users,
  (SELECT COUNT(DISTINCT app_name) FROM {SRC})                  AS apps,
  (SELECT COUNT(*) FROM sensitive_events)                       AS sensitive_events;

-- EDA_01: Schema for events (DuckDB DESCRIBE)
DESCRIBE events;

-- EDA_02: Schema for sensitive_events
DESCRIBE sensitive_events;

-- EDA_03: Nulls per column (events)
SELECT column_name,
       SUM(nulls) AS nulls,
       SUM(rows)  AS rows,
       100.0 * SUM(nulls) / NULLIF(SUM(rows),0) AS pct_nulls
FROM (
  SELECT 'ts' AS column_name, COUNT(*) AS rows, SUM(CASE WHEN ts IS NULL THEN 1 ELSE 0 END) AS nulls FROM {SRC} UNION ALL
  SELECT 'user_id', COUNT(*), SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) FROM {SRC} UNION ALL
  SELECT 'url', COUNT(*), SUM(CASE WHEN url IS NULL THEN 1 ELSE 0 END) FROM {SRC} UNION ALL
  SELECT 'domain', COUNT(*), SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END) FROM {SRC} UNION ALL
  SELECT 'app_name', COUNT(*), SUM(CASE WHEN app_name IS NULL THEN 1 ELSE 0 END) FROM {SRC} UNION ALL
  SELECT 'clipboard_text', COUNT(*), SUM(CASE WHEN clipboard_text IS NULL THEN 1 ELSE 0 END) FROM {SRC}
)
GROUP BY 1
ORDER BY pct_nulls DESC;

-- EDA_04: Top users
SELECT user_id, COUNT(*) AS events
FROM {SRC}
GROUP BY 1
ORDER BY events DESC
LIMIT 50;

-- EDA_05: Top domains
SELECT domain, COUNT(*) AS events
FROM {SRC}
GROUP BY 1
ORDER BY events DESC
LIMIT 50;

-- EDA_06: Top apps
SELECT app_name, COUNT(*) AS events, COUNT(DISTINCT user_id) AS users
FROM {SRC}
GROUP BY 1
ORDER BY users DESC, events DESC
LIMIT 25;

-- EDA_07: Events by hour-of-day
SELECT EXTRACT(hour FROM ts) AS hour, COUNT(*) AS events
FROM {SRC}
GROUP BY 1
ORDER BY 1;

-- EDA_08: Sensitive category distribution
SELECT category, COUNT(*) AS events
FROM sensitive_events
GROUP BY 1
ORDER BY events DESC;

-- ============ TASK 1 – SaaS Discovery ============

-- T1_01: Top apps by users/events
SELECT app_name,
       COUNT(*) AS total_events,
       COUNT(DISTINCT user_id) AS unique_users
FROM {SRC}
GROUP BY 1
ORDER BY unique_users DESC, total_events DESC
LIMIT 50;

-- T1_02: Daily users per app
SELECT date_trunc('day', ts) AS day,
       app_name,
       COUNT(*) AS events,
       COUNT(DISTINCT user_id) AS users
FROM {SRC}
GROUP BY 1,2
ORDER BY 1,2;

-- T1_03: User ↔ App matrix (events)
SELECT user_id, app_name, COUNT(*) AS events
FROM {SRC}
GROUP BY 1,2;

-- T1_04: App risk scores (weights configurable; ensure table exists)
-- Create helper table once (can be done outside SQL pack):
--   CREATE OR REPLACE TABLE app_risk_weight(app_name VARCHAR, weight DOUBLE);
--   INSERT INTO app_risk_weight VALUES
--     ('ChatGPT',3.0),('Claude',3.0),('Gemini',3.0),('Copilot',2.5),
--     ('Dropbox',2.0),('Google Drive',2.0),('Box',2.0),('WeTransfer',2.5),
--     ('Slack',1.5),('Notion',1.5),('Atlassian',1.0),('Figma',1.0),
--     ('Zoom',1.0),('MS Teams',1.0),('Code Hosting',2.0);

WITH base AS (
  SELECT user_id, app_name, COUNT(*) AS events
  FROM {SRC}
  GROUP BY 1,2
)
SELECT b.app_name,
       SUM(b.events * COALESCE(w.weight,1.0)) AS risk_score,
       SUM(b.events) AS events,
       COUNT(DISTINCT b.user_id) AS users
FROM base b
LEFT JOIN app_risk_weight w USING(app_name)
GROUP BY 1
ORDER BY risk_score DESC;

-- ============ TASK 2 – Sensitive Leakage ============

-- T2_01: Sensitive categories over time
SELECT date_trunc('day', ts) AS day, category, COUNT(*) AS cnt
FROM sensitive_events
GROUP BY 1,2
ORDER BY 1,2;

-- T2_02: Sensitive by app
SELECT COALESCE(app_name,'Unknown') AS app_name,
       category,
       COUNT(*) AS events
FROM sensitive_events
GROUP BY 1,2
ORDER BY events DESC;

-- T2_03: Sensitive by user
SELECT user_id, category, COUNT(*) AS events
FROM sensitive_events
GROUP BY 1,2
ORDER BY events DESC;

-- T2_04: Top risky destinations (GenAI & cloud)
SELECT app_name, domain, COUNT(*) AS events
FROM {SRC}
WHERE app_name IN ('ChatGPT','Claude','Gemini','Copilot','Dropbox','Google Drive','Box','WeTransfer')
GROUP BY 1,2
ORDER BY events DESC
LIMIT 200;

-- T2_05: Sensitive examples table (for screenshots)
SELECT
  date_trunc('minute', e.ts) AS ts_minute,
  e.user_id,
  e.app_name,
  s.category,
  e.domain,
  LEFT(e.clipboard_text, 180) AS sample_clipboard
FROM {SRC} e
JOIN sensitive_events s USING (ts, user_id, domain, app_name)
WHERE e.clipboard_text IS NOT NULL
ORDER BY ts_minute DESC
LIMIT 200;
