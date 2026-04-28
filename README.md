# 🎯 noury_sniper — Linux DFIR Fast Triage Profile

> **Mid-tier fast triage profile for [UAC (Unix Artifacts Collector)](https://github.com/tclahr/uac)**  
> Optimized for **15-minute targeted collection** with maximum forensic value — built for real-world incident response.

---

## 🧠 What is noury_sniper?

`noury_sniper` is a **custom UAC profile** engineered for Linux Digital Forensics and Incident Response (DFIR). It was designed to cut through the noise — skipping everything that doesn't matter and going straight for the artifacts that tell the story.

Unlike default profiles that collect everything and waste time, `noury_sniper` is **surgical**. It targets the exact layers an analyst needs during live triage: volatile memory state, network activity, persistence mechanisms, user activity, stealth indicators, and log evidence — all in a single disciplined run.

### ⚡ Why noury_sniper is Fast, Efficient & Effective

| Feature | Benefit |
|---|---|
| **Scoped artifact selection** | No bloat — only what matters for triage |
| **Layered collection order** | Volatile data first (memory dies), then persistent |
| **Time-bounded collection** | `--start-date` flag limits scope to exact window |
| **Rootkit detection built-in** | `chkrootkit` runs as part of the profile |
| **Bodyfile generation** | Enables full filesystem timeline in seconds |
| **~15 min collection time** | Faster than most single-category default profiles |
| **Minimal disk footprint** | Targeted output — no GB of irrelevant data |

---

## 📂 Profile Structure — `noury_sniper.yaml`

```yaml
name: noury_sniper
description: Mid-tier fast triage. Optimized for 15-minute collection.
artifacts:

  # --- 1. MODIFIERS ---
  - live_response/modifiers/*

  # --- 2. VOLATILE DATA (Memory, Processes, Network) ---
  - live_response/process/ps.yaml
  - live_response/process/pstree.yaml
  - live_response/process/lsof.yaml
  - live_response/process/pstat.yaml
  - live_response/process/procstat.yaml
  - live_response/process/fstat.yaml
  - live_response/network/*

  # --- 3. STEALTH & SYSTEM STATE ---
  - chkrootkit/*
  - live_response/system/*

  # --- 4. CONFIGURATIONS & PERSISTENCE (On-Disk) ---
  - files/system/*

  # --- 5. USER ACTIVITY & HISTORY ---
  - files/shell/*
  - files/ssh/*
  - files/applications/git.yaml
  - files/applications/wget.yaml
  - files/applications/lesshst.yaml
  - files/applications/nano.yaml
  - files/applications/viminfo.yaml

  # --- 6. LOGS (Evidence) ---
  - files/logs/*
  - files/browsers/*
  - files/packages/*
  - bodyfile/bodyfile.yaml
```

### 🔍 Collection Layer Breakdown

**Layer 1 — Modifiers**: Global settings that tune how UAC behaves during the run.

**Layer 2 — Volatile Data**: This is collected FIRST because it's the most fragile. Process tables, open file descriptors, active sockets, and network connections disappear when the machine is powered off or the attacker covers tracks.

**Layer 3 — Stealth & System State**: `chkrootkit` sweeps for known rootkit signatures. Live system state captures logged-in users, mounted filesystems, scheduled jobs, and service states.

**Layer 4 — Persistence**: On-disk configuration files, systemd units, cron jobs, init scripts, and other persistence vectors attackers love to abuse.

**Layer 5 — User Activity**: Shell histories (bash, zsh, fish), SSH known_hosts and authorized_keys, git logs, wget history, editor artifacts (vim, nano). These tell you *who did what* on the box.

**Layer 6 — Logs & Evidence**: Auth logs, syslog, kern.log, browser activity, package manager history (apt/yum), and a full filesystem bodyfile for timeline reconstruction.

---

## 🚀 How to Run

### Prerequisites

- UAC installed and accessible: [https://github.com/tclahr/uac](https://github.com/tclahr/uac)
- This profile placed in `uac/profiles/noury_sniper.yaml`
- Run as **root** (`sudo`) for full artifact access
- Output directory created and writable

---

### ▶️ Collect for the Last Month (30 days)

Use this when you need to scope the investigation to the past month — for example, April 2026:

```bash
sudo ./uac -p profiles/noury_sniper.yaml \
  --start-date 2026-04-01 \
  /home/elnoury/DFIR_Artifacts/new1
```

> **What `--start-date` does:** UAC filters file collection and log parsing to only include artifacts modified or written **on or after** the given date. This dramatically reduces output size and collection time by skipping older, irrelevant data. You're telling the tool: *"I only care about what happened from this date forward."*

---

### ▶️ Collect for One Specific Day

When you know the exact day of the incident:

```bash
sudo ./uac -p profiles/noury_sniper.yaml \
  --start-date 2026-04-21 \
  /home/elnoury/DFIR_Artifacts/new1
```

> This is the most precise mode. Collecting a single day means the smallest output, fastest run time, and the cleanest dataset for analysis. Use this when you have an IOC or alert timestamp pinpointing the incident.

---

### ▶️ Collect for One Week

When your window is the past 7 days:

```bash
sudo ./uac -p profiles/noury_sniper.yaml \
  --start-date 2026-04-21 \
  /home/elnoury/DFIR_Artifacts/new1
```

> Set `--start-date` to exactly 7 days before today. For a week ending April 28, 2026, start from April 21. The collection will capture all relevant artifacts from that 7-day window forward.

---

### ⏱️ Time Customization Summary

```
--start-date YYYY-MM-DD
```

| Window | Example Command |
|---|---|
| Single day | `--start-date 2026-04-21` |
| One week | `--start-date 2026-04-21` *(7 days back)* |
| One month | `--start-date 2026-04-01` *(start of month)* |
| Full April 2026 | `--start-date 2026-04-01` |

The `--start-date` parameter is the core of `noury_sniper`'s speed advantage. By scoping collection to a precise time window, you avoid collecting months of logs, old configs, and stale data that adds GB of noise with zero investigative value.

---

## 📊 Timeline Analysis — Bodyfile Parsing

After collection, the bodyfile (`bodyfile.txt`) is your most powerful artifact. It contains MAC timestamps for every file on the filesystem. Use the following `gawk` command to extract a clean, sortable CSV timeline filtered to April 2026.

### Parse Bodyfile → Timeline CSV

```bash
gawk -F'|' 'BEGIN {print "Date_Time,Size,Activity,Mode,UID,GID,Path"}
$8 >= 1743465600 {
  print strftime("%Y-%m-%d %H:%M:%S", $8) "," $7 ",Modified," $4 "," $5 "," $6 "," $2
}' bodyfile.txt | grep "2026-04" > april_fixed1.csv
```

### Command Breakdown

| Component | Purpose |
|---|---|
| `-F'|'` | Sets the field separator to pipe `\|` (bodyfile format) |
| `BEGIN {print ...}` | Writes a clean CSV header row |
| `$8 >= 1743465600` | Unix timestamp filter — `1743465600` = **April 1, 2026 00:00:00 UTC** |
| `strftime(...)` | Converts Unix timestamps to human-readable `YYYY-MM-DD HH:MM:SS` |
| `$7` | File size in bytes |
| `$4` | File permissions/mode |
| `$5 / $6` | UID and GID of file owner |
| `$2` | Full file path |
| `grep "2026-04"` | Final filter — ensures only April 2026 entries make it into the output |
| `> april_fixed1.csv` | Saves the timeline to a CSV file for import into Excel, Timeline Explorer, or any SIEM |

### 📅 Useful Unix Timestamps for Date Filtering

| Date | Unix Timestamp |
|---|---|
| April 1, 2026 00:00 UTC | `1743465600` |
| April 21, 2026 00:00 UTC | `1745193600` |
| March 1, 2026 00:00 UTC | `1740787200` |
| January 1, 2026 00:00 UTC | `1735689600` |

> 💡 Use [https://www.unixtimestamp.com](https://www.unixtimestamp.com) to generate your own epoch timestamps for custom date ranges.

### Importing the CSV

The output `april_fixed1.csv` can be opened directly in:
- **Microsoft Excel** / **LibreOffice Calc** — for manual analysis
- **Timeline Explorer** (Eric Zimmerman) — recommended for large timelines
- **Kibana / Splunk** — for SIEM-based correlation

---

## 🧩 Full Workflow Example

```bash
# Step 1: Run the profile — collect April 2026 artifacts
sudo ./uac -p profiles/noury_sniper.yaml \
  --start-date 2026-04-01 \
  /home/elnoury/DFIR_Artifacts/new1

# Step 2: Navigate to the output directory
cd /home/elnoury/DFIR_Artifacts/new1

# Step 3: Extract bodyfile from the archive (if compressed)
# UAC outputs a .tar.gz — extract it first
tar -xzf uac-*.tar.gz

# Step 4: Parse bodyfile into timeline CSV
gawk -F'|' 'BEGIN {print "Date_Time,Size,Activity,Mode,UID,GID,Path"}
$8 >= 1743465600 {
  print strftime("%Y-%m-%d %H:%M:%S", $8) "," $7 ",Modified," $4 "," $5 "," $6 "," $2
}' bodyfile.txt | grep "2026-04" > april_fixed1.csv

# Step 5: Open CSV in your analysis tool of choice
```

---

## 📋 Requirements

- **OS**: Linux (any major distro — tested on Ubuntu, RHEL, Debian)
- **Privileges**: Root (`sudo`) required
- **UAC Version**: v2.x or later
- **Tools**: `gawk`, `bash` (pre-installed on all major distros)
- **Disk Space**: ~500MB–2GB depending on log volume and time window

---

## 👤 Author

**El Noury** — DFIR Analyst  
Profile designed for real-world Linux incident response — fast, focused, and forensically sound.

---

## 📜 License

This profile is open for use in any DFIR investigation. Attribution appreciated.  
UAC itself is licensed under the [Apache 2.0 License](https://github.com/tclahr/uac/blob/main/LICENSE).

---

> *"Speed without sacrifice. noury_sniper gets the evidence before the attacker covers their tracks."*
