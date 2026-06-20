# 🛡️ Cyber Security Threat Analytics Dashboard

An interactive **Data Analytics Dashboard** built on the  **NSL-KDD Network Intrusion Detection dataset** . It transforms raw network connection records into actionable security insights through KPIs, interactive Plotly charts, and a 4-page Streamlit interface.

> 📄 **Full project documentation:** [`CyberSecurityDashboard_Documentation.docx`](https://github.com/Nain-007sh/cyber-security-threat-analytics-dashboard/blob/main/CyberSecurityDashboard_Documentation.docx)

---

## 📌 Project Overview

This dashboard follows a pure analytics pipeline — no machine learning model is trained:

```
Raw Dataset → Data Cleaning → Feature Engineering → KPI Creation → Interactive Dashboard
```

The `class` column (`normal` / `anomaly`) already present in the source training data is used as-is to power threat analytics.

---

## 🎯 Objectives

* Understand attack patterns across protocols, services, and TCP flags
* Monitor security activity and detect high-risk events using composite scoring
* Analyze traffic behavior (source vs destination bytes, traffic volume categories)
* Identify the most targeted services and connection types
* Provide a transparent, auditable data-quality view of the underlying dataset
* Build a fully filterable dashboard with 6 dynamic sidebar filters

---

## 📊 Dataset Information

**Source:** NSL-KDD Network Intrusion Detection dataset (Kaggle)

| Property                    | Value                                                |
| --------------------------- | ---------------------------------------------------- |
| Train_data.csv              | 25,192 rows · 42 columns · includes `class`label |
| Test_data.csv               | 22,544 rows · 41 columns · no `class`label       |
| Combined rows (after dedup) | 47,679                                               |
| Original columns            | 42 (41 features +`class`)                          |
| Engineered columns added    | 7                                                    |
| Missing values in source    | 0                                                    |
| Duplicates removed          | 57                                                   |

> ⚠️ **Honest note:** The NSL-KDD dataset has  **no date/timestamp column** . Any chart needing a sequence axis uses `record_index` (row order), clearly labeled throughout. The sidebar  **Date Filter is intentionally disabled** . `Test_data.csv` rows are labeled `"unlabeled"` — never guessed — so no fabricated ground truth is introduced.

---

## ⚙️ Feature Engineering

All 7 features are derived strictly from real dataset columns — no fabricated values.

| Feature                 | Formula / Logic                                                              | Source Columns                                                                          |
| ----------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `total_traffic`       | `src_bytes + dst_bytes`                                                    | src_bytes, dst_bytes                                                                    |
| `traffic_category`    | Data-driven terciles → Low / Medium / High                                  | total_traffic                                                                           |
| `threat_level`        | Weighted composite score → Low / Medium / High                              | class, root_shell, num_failed_logins, wrong_fragment, su_attempted, serror_rate         |
| `connection_category` | Duration bucket → Instant / Short / Medium / Long                           | duration                                                                                |
| `risk_score`          | Weighted 0–100 composite (anomaly +40, root_shell +20, su_attempted +10 …) | class, root_shell, su_attempted, num_failed_logins, wrong_fragment, urgent, serror_rate |
| `attack_severity`     | Tier from risk_score → Low / Medium / High / Critical                       | risk_score                                                                              |
| `record_index`        | Row sequence number (NOT a timestamp)                                        | row order                                                                               |

---

## 📈 KPIs

| KPI                          | Formula                                  |
| ---------------------------- | ---------------------------------------- |
| Total Records                | `COUNT(*)`                             |
| Total Threat Events          | `COUNT(class = 'anomaly')`             |
| Threat Percentage            | `Total Threats / Total Records × 100` |
| Traffic Volume               | `SUM(total_traffic)`                   |
| High Risk Events             | `COUNT(threat_level = 'High')`         |
| Unique Services              | `COUNT(DISTINCT service)`              |
| Total Protocol Types         | `COUNT(DISTINCT protocol_type)`        |
| Avg Connection Duration      | `AVG(duration)`                        |
| Most Frequent Attack Service | `MODE(service WHERE class='anomaly')`  |
| Data Completeness Score      | `(1 − missing/total_cells) × 100`    |

---

## 🗂️ Dashboard Pages

### 🏠 Page 1 — Executive Overview

KPI cards · Attack trend (binned record sequence) · Threat distribution donut · Protocol analysis · Top attack categories · Protocol × Service heatmap · Traffic distributions · Connection duration · Service usage · Auto-generated insights panel

### 🔴 Page 2 — Threat Analysis

Attack-by-flag/protocol bars · Attack severity pie · Threat level by protocol · Risk score histogram · Most targeted services · Protocol × Flag heatmap · serror_rate vs rerror_rate scatter

### 📡 Page 3 — Traffic Analysis

Traffic by protocol · Top 10 services by traffic · Traffic category split · src/dst bytes scatter · Duration histogram · Traffic by connection category · Same-service rate distribution · Count vs srv_count scatter

### 📊 Page 4 — Data Quality

Missing values check · Outlier counts (IQR×3) · Class balance · Boxplots · Cleaning summary table · Feature correlation matrix (10 columns)

---

## 🎛️ Sidebar Filters (all dynamic)

All 6 filters affect every KPI card and every chart across all 4 pages simultaneously.

| Filter           | Column               | Values                                       |
| ---------------- | -------------------- | -------------------------------------------- |
| Protocol Type    | `protocol_type`    | tcp, udp, icmp                               |
| Service Type     | `service`          | http, ftp, smtp, private, …                 |
| Attack Type      | `class`            | normal, anomaly, unlabeled                   |
| Threat Level     | `threat_level`     | High, Medium, Low                            |
| Traffic Category | `traffic_category` | Low Traffic, Medium Traffic, High Traffic    |
| Connection Flag  | `flag`             | SF, S0, REJ, RSTO, …                        |
| Date Filter      | —                   | **Disabled**— no timestamp in NSL-KDD |

---

## 🛠️ Tech Stack

| Technology | Version | Purpose                              |
| ---------- | ------- | ------------------------------------ |
| Python     | 3.10+   | Core language                        |
| Streamlit  | 1.38.0  | Dashboard framework                  |
| Plotly     | 5.24.1  | All interactive charts               |
| Pandas     | 2.2.2   | Data processing & filtering          |
| NumPy      | 1.26.4  | Numeric operations, outlier capping  |
| Custom CSS | —      | Dark cybersecurity-themed UI         |
| SQL        | —      | 12 MySQL/PostgreSQL analysis queries |

---

## 📁 Project Structure

```
CyberSecurityDashboard/
│
├── data/
│   ├── Train_data.csv                           # Raw NSL-KDD training set (25,192 rows)
│   ├── Test_data.csv                            # Raw NSL-KDD test set (22,544 rows)
│   ├── cleaned_data.csv                         # Cleaned + engineered output (47,679 rows, 49 cols)
│   └── quality_log.json                         # Cleaning/outlier audit log
│
├── notebooks/
│   └── data_preparation.py                      # Reproducible cleaning & feature engineering script
│
├── sql/
│   └── queries.sql                              # 12 analysis queries (MySQL / PostgreSQL)
│
├── assets/                                      # Reserved for screenshots / static assets
│
├── app.py                                       # Streamlit dashboard entry point
├── style.css                                    # Dark theme dashboard styling
├── requirements.txt                             # Python dependencies
├── CyberSecurityDashboard_Documentation.docx    # 📄 Full project documentation
└── README.md
```

---

## 🚀 Installation & Run Instructions

1. **Extract the project** and open it in VS Code or any terminal.
2. **Create a virtual environment (recommended):**

   ```bash
   python -m venv venv
   venv\Scripts\activate        # Windows
   source venv/bin/activate     # macOS / Linux
   ```
3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```
4. **(Optional) Re-generate `cleaned_data.csv` from raw files:**

   ```bash
   python notebooks/data_preparation.py
   ```

   > `cleaned_data.csv` is already included — this step is optional.
   >
5. **Run the dashboard:**

   ```bash
   streamlit run app.py
   ```
6. Open the URL shown in the terminal — typically `http://localhost:8501`

---

## 🐛 Known Issues & Fixes

| Error                                                | Fix                                                     |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `UnicodeDecodeError: 'charmap' codec`              | ✅ Fixed —`open()`calls now use `encoding="utf-8"` |
| `ModuleNotFoundError: No module named 'streamlit'` | Run `pip install -r requirements.txt`                 |
| `FileNotFoundError: data/cleaned_data.csv`         | Run `python notebooks/data_preparation.py`            |
| Port 8501 already in use                             | Run `streamlit run app.py --server.port 8502`         |

---

## 💡 Key Insights

* A significant share of network connections are flagged as anomalies — reflecting the dataset's intrusion-detection research design
* **TCP** is the dominant protocol by both connection count and total traffic volume
* A small set of services (`http`, `private`, `domain_u`) accounts for the majority of both normal and anomalous traffic
* Most connections have `duration = 0`, indicating short-lived / single-packet sessions dominate this dataset
* `serror_rate` (SYN error rate) is strongly correlated with the anomaly class — a reliable proxy indicator

---

## 🔮 Future Improvements

* Add real time-series dimension if a dataset with genuine timestamps becomes available
* Add drill-down detail tables per chart for record-level investigation
* Add CSV export of filtered views for external reporting
* Add user authentication for production deployment
* Add automated data-quality alerts and train/test distribution drift detection
* Add a machine learning page with anomaly classification model comparison
* Deploy to Streamlit Cloud or Docker for public access

---

## 📄 Documentation

Full project documentation is available in  **[`CyberSecurityDashboard_Documentation.docx`](https://github.com/Nain-007sh/cyber-security-threat-analytics-dashboard/blob/main/CyberSecurityDashboard_Documentation.docx)** , covering:

* Complete data pipeline walkthrough
* All KPI formulas and definitions
* Feature engineering logic
* SQL query reference table
* Installation troubleshooting guide
* Key analytical insights
* Documented assumptions

---

## 📷 Screenshots


---
