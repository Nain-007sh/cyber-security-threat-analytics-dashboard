-- ═══════════════════════════════════════════════════════════════════════════
-- Cyber Security Threat Analytics Dashboard — SQL Queries
-- Compatible with MySQL / PostgreSQL
-- Table assumed: cleaned_data  (loaded from cleaned_data.csv)
-- All columns referenced below are REAL columns present in cleaned_data.csv
-- ═══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────
-- 1. TOP ATTACK CATEGORIES (by service, anomaly records only)
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    service,
    COUNT(*) AS attack_count
FROM cleaned_data
WHERE class = 'anomaly'
GROUP BY service
ORDER BY attack_count DESC
LIMIT 10;


-- ─────────────────────────────────────────────────────────────────────────
-- 2. TRAFFIC BY PROTOCOL
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    protocol_type,
    SUM(total_traffic) AS total_traffic_bytes,
    COUNT(*)            AS connection_count,
    ROUND(AVG(total_traffic), 2) AS avg_traffic_per_connection
FROM cleaned_data
GROUP BY protocol_type
ORDER BY total_traffic_bytes DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 3. HIGH RISK ACTIVITIES (ThreatLevel = High)
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    protocol_type,
    service,
    flag,
    src_bytes,
    dst_bytes,
    risk_score,
    threat_level,
    class
FROM cleaned_data
WHERE threat_level = 'High'
ORDER BY risk_score DESC
LIMIT 100;


-- ─────────────────────────────────────────────────────────────────────────
-- 4. SERVICE-LEVEL ANALYSIS (connections, attacks, avg risk per service)
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    service,
    COUNT(*) AS total_connections,
    SUM(CASE WHEN class = 'anomaly' THEN 1 ELSE 0 END) AS anomaly_count,
    ROUND(
        100.0 * SUM(CASE WHEN class = 'anomaly' THEN 1 ELSE 0 END) / COUNT(*), 2
    ) AS anomaly_pct,
    ROUND(AVG(risk_score), 2) AS avg_risk_score
FROM cleaned_data
GROUP BY service
ORDER BY anomaly_count DESC
LIMIT 15;


-- ─────────────────────────────────────────────────────────────────────────
-- 5. THREAT LEVEL SUMMARY
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    threat_level,
    COUNT(*) AS event_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM cleaned_data), 2) AS pct_of_total,
    ROUND(AVG(risk_score), 2) AS avg_risk_score
FROM cleaned_data
GROUP BY threat_level
ORDER BY avg_risk_score DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 6. ATTACK SEVERITY BREAKDOWN
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    attack_severity,
    COUNT(*) AS event_count,
    ROUND(AVG(risk_score), 2) AS avg_risk_score,
    ROUND(AVG(duration), 2)   AS avg_duration
FROM cleaned_data
GROUP BY attack_severity
ORDER BY avg_risk_score DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 7. PROTOCOL x FLAG ATTACK DISTRIBUTION (for heatmap)
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    protocol_type,
    flag,
    COUNT(*) AS count
FROM cleaned_data
WHERE class = 'anomaly'
GROUP BY protocol_type, flag
ORDER BY protocol_type, count DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 8. CONNECTION DURATION CATEGORY DISTRIBUTION
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    connection_category,
    COUNT(*)                 AS connection_count,
    ROUND(AVG(duration), 2)  AS avg_duration_seconds,
    SUM(total_traffic)       AS total_traffic_bytes
FROM cleaned_data
GROUP BY connection_category
ORDER BY avg_duration_seconds DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 9. TRAFFIC CATEGORY DISTRIBUTION
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    traffic_category,
    COUNT(*) AS record_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM cleaned_data), 2) AS pct_of_total
FROM cleaned_data
GROUP BY traffic_category;


-- ─────────────────────────────────────────────────────────────────────────
-- 10. DATA QUALITY — CLASS BALANCE CHECK
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    class,
    COUNT(*) AS record_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM cleaned_data), 2) AS pct_of_total
FROM cleaned_data
GROUP BY class
ORDER BY record_count DESC;


-- ─────────────────────────────────────────────────────────────────────────
-- 11. TOP 10 HIGHEST RISK CONNECTIONS
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    protocol_type, service, flag, duration,
    src_bytes, dst_bytes, risk_score, attack_severity, class
FROM cleaned_data
ORDER BY risk_score DESC
LIMIT 10;


-- ─────────────────────────────────────────────────────────────────────────
-- 12. FAILED LOGIN ANALYSIS (security indicator, native column)
-- ─────────────────────────────────────────────────────────────────────────
SELECT
    service,
    SUM(num_failed_logins) AS total_failed_logins,
    COUNT(*) AS connection_count
FROM cleaned_data
WHERE num_failed_logins > 0
GROUP BY service
ORDER BY total_failed_logins DESC;
