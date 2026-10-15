#!/usr/bin/env python3
"""
ProcSentinel: Detection of Masqueraded Processes in Volatile Memory
Volatility Analysis Runner

University of Hail - Graduation Project
College of Computer Science and Engineering
Department of Computer Science

December 2025

Tested with: Volatility 3 (2.26.x). Python 3.10+.

Usage:
  python runner.py --image memory.raw --case case1 \
    --detections detections.yaml --baseline baseline.yaml --outdir out \
    --api-key YOUR_IP_ENRICHMENT_API_KEY

Notes:
- Keeps stdout very chatty so you can see exactly what runs.
- Handles Win7 limitations gracefully (skips unsupported plugins).
- Places "-r csv" BEFORE plugin name when format=csv (Vol3 quirk).
"""

import argparse, csv, json, os, re, shutil, subprocess, sys, time, textwrap
import logging
import html as _html
import unicodedata
from pathlib import Path
from datetime import datetime, UTC
from typing import Dict, List, Any, Tuple
import requests
import ipaddress
from io import StringIO
import traceback

# ---------------------------------------------------------------------------
# Logging — use INFO by default; set env PROCSENTINEL_DEBUG=1 for verbose output
# All runner output goes through this logger so the Streamlit progress screen
# can parse [+], [i], [warn] prefixes from stdout cleanly.
# ---------------------------------------------------------------------------
_log_level = logging.DEBUG if os.environ.get("PROCSENTINEL_DEBUG") == "1" else logging.INFO
logging.basicConfig(level=_log_level, format="%(message)s", stream=sys.stdout)
log = logging.getLogger("procsentinel")

try:
    import yaml
except Exception as e:
    log.error("Please: pip install pyyaml")
    sys.exit(2)

# ---------------------------
# Helpers
# ---------------------------

def sh(cmd: List[str], capture=True, cwd=None) -> Tuple[int, str]:
    """Run a shell command. Returns (rc, output)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            cwd=cwd,
            text=True
        )
        return proc.returncode, (proc.stdout or "")
    except FileNotFoundError:
        return 127, f"[ENOENT] {cmd[0]} not found on PATH"
    except Exception as e:
        return 1, f"[ERROR] {' '.join(cmd)} :: {e}"


def find_vol_binary(prefer_list: List[str]) -> str:
    for name in prefer_list:
        rc, _ = sh(["which", name])
        if rc == 0:
            return name
    return ""


def ensure_dirs(outdir: Path):
    log.debug(f"Ensuring output directories exist at: {outdir}")
    (outdir / "artifacts").mkdir(parents=True, exist_ok=True)
    (outdir / "logs").mkdir(exist_ok=True)
    log.debug(f"Directories created/exist.")


def write_file(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8", errors="ignore")


def now_iso() -> str:
    return datetime.now(UTC).isoformat() + "Z"


def compile_any_contains_to_regex(parts: List[str]) -> re.Pattern:
    escaped = []
    for p in parts:
        escaped.append(re.escape(p))
    regex = "(" + "|".join(escaped) + ")"
    return re.compile(regex, re.IGNORECASE)


def in_cidrs(ip: str, cidrs: List[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for block in cidrs:
            if addr in ipaddress.ip_network(block, strict=False):
                return True
    except Exception:
        return False
    return False


def get_ip_info(ip: str, api_key: str) -> Dict[str, str]:
    info = {"country": "N/A", "isp": "N/A", "reputation": "N/A"}
    if not api_key:
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            if response.status_code == 200:
                data = response.json()
                info["country"] = data.get("country", "N/A")
                info["isp"] = data.get("org", "N/A")
                info["reputation"] = "Clean (ipinfo.io fallback)"
        except Exception as e:
            log.warning(f"ipinfo.io fallback failed for {ip}: {e}")
        return info

    abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    try:
        log.info(f"Querying AbuseIPDB for IP: {ip}...")
        response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=5)
        response.raise_for_status()

        data = response.json().get('data', {})
        info["country"] = data.get("countryCode", "N/A")
        info["isp"] = data.get("isp", "N/A")
        abuse_score = data.get("abuseConfidenceScore", 0)
        if abuse_score > 60:
            info["reputation"] = "Malicious"
        elif abuse_score > 20:
            info["reputation"] = "Suspicious"
        else:
            info["reputation"] = "Clean"
        info["abuse_reports"] = data.get("totalReports", 0)
        info["last_reported"] = data.get("lastReportedAt", "N/A")
        log.info(f"AbuseIPDB result for {ip}: Country={info['country']}, Reputation={info['reputation']}")

    except requests.exceptions.HTTPError as e:
        log.error(f"AbuseIPDB HTTP error for {ip}: {e.response.status_code} - {e.response.text}")
        info["reputation"] = f"API Error ({e.response.status_code})"
    except requests.exceptions.ConnectionError as e:
        log.error(f"AbuseIPDB connection error for {ip}: {e}")
        info["reputation"] = "Network Error"
    except requests.exceptions.Timeout:
        log.error(f"AbuseIPDB API request timed out for {ip}.")
        info["reputation"] = "Timeout"
    except Exception as e:
        log.error(f"Unexpected error during AbuseIPDB call for {ip}: {e}")
        info["reputation"] = "Unknown Error"
    
    return info


# ---------------------------
# Volatility Runner
# ---------------------------

def run_plugin(vol: str, image: str, plugin: str, fmt: str, outdir: Path) -> str:
    base = [vol, "-f", image, "--quiet"]
    if fmt == "csv":
        cmd = base + ["-r", "csv", plugin]
    else:
        cmd = base + [plugin]

    safe_plugin_name = plugin.replace(".", "_")
    ext = "csv" if fmt == "csv" else "txt"
    raw_path = outdir / "artifacts" / f"{safe_plugin_name}.{ext}"

    log.debug(f"Attempting to run Volatility command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
            errors="replace"
        )
        out = proc.stdout
        log.debug(f"Raw output from {plugin} (first 500 chars):\n{out[:500]}...")
        write_file(raw_path, out)
        return out
    except subprocess.CalledProcessError as e:
        error_message = f"[ERROR] Plugin '{plugin}' failed with exit code {e.returncode}. Output:\n{e.stdout}"
        log.error(error_message)
        return error_message
    except Exception as e:
        error_message = f"[ERROR] Plugin '{plugin}' failed unexpectedly: {e}"
        log.error(error_message)
        return error_message


def try_plugin_with_fallbacks(vol: str, image: str, name: str, fmt: str, fallbacks: List[str], outdir: Path) -> Tuple[str, str]:
    content = run_plugin(vol, image, name, fmt, outdir)
    if "invalid choice" in content or "not supported" in content or "Traceback" in content or "Unsatisfied requirement" in content:
        log.debug(f"Plugin {name} failed or gave invalid output. Trying fallbacks: {fallbacks}")
        for alt in fallbacks or []:
            alt_content = run_plugin(vol, image, alt, fmt, outdir)
            if "invalid choice" not in alt_content and "Traceback" not in alt_content and "Unsatisfied requirement" not in alt_content:
                log.debug(f"Fallback {alt} successful.")
                return alt, alt_content
    return name, content


def detect_os(info_text: str) -> str:
    if "NtSystemRoot" in info_text or "IsPAE" in info_text:
        return "windows"
    if "Linux" in info_text or "linux" in info_text:
        return "linux"
    if "Darwin" in info_text or "Mac" in info_text:
        return "macos"
    return "windows"


# ---------------------------
# Parsers
# ---------------------------

def parse_csv(text: str) -> List[Dict[str, str]]:
    if not text or not text.strip():
        log.debug("parse_csv received empty text or only whitespace lines.")
        return []

    reader = csv.reader(StringIO(text))
    header = None
    for _ in range(10):
        try:
            record = next(reader)
        except StopIteration:
            break

        if len(record) > 1 and not record[0].strip().lower().startswith("volatility 3"):
            header = [field.strip() for field in record]
            break

    if header is None:
        log.debug("parse_csv could not find a CSV header in the first 10 records.")
        return []

    rows = []
    malformed_rows = 0
    for record in reader:
        if not record or not any(field.strip() for field in record):
            continue
        if len(record) > len(header):
            malformed_rows += 1
            continue
        record += [""] * (len(header) - len(record))
        rows.append({
            header[i]: record[i].strip()
            for i in range(len(header))
        })

    if malformed_rows:
        log.debug(f"parse_csv skipped {malformed_rows} rows with more fields than the header.")
    log.debug(f"parse_csv parsed {len(rows)} rows with headers: {header}")
    return rows


def kv_parse(text: str) -> Dict[str, str]:
    d = {}
    for line in text.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d[k.strip()] = v.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


# ---------------------------
# Engines
# ---------------------------
def eng_process_pid_match(pslist_rows: List[Dict[str, str]], target_pid: int):
    findings = []
    for r in pslist_rows:
        try:
            if int(r.get("PID","")) == target_pid:
                findings.append({"pid": target_pid, "name": r.get("ImageFileName","") or r.get("Name","")})
                break
        except (ValueError, TypeError):
            continue
    return findings

def eng_unknown_process_name(pslist_rows, baseline, oskey="windows"):
    wl = set((baseline.get("process_whitelist", {}).get(oskey, [])) or [])
    findings = []
    for r in pslist_rows:
        name = r.get("ImageFileName", "") or r.get("Name", "")
        pid  = r.get("PID", "")
        if name and (name.lower() not in [n.lower() for n in wl]):
            findings.append({"pid": pid, "name": name, "path": r.get("Path","")})
    return findings

def eng_psxview_hidden(rows):
    # Processes that must ALWAYS appear in pslist on a live Windows system.
    # If any of these appear in psscan but NOT pslist → genuine DKOM hiding.
    PERSISTENT_SYSTEM_PROCESSES = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
        'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe', 'spoolsv.exe',
        'explorer.exe', 'dwm.exe',
        'conhost.exe', 'dllhost.exe', 'rundll32.exe',
    }
    # Short-lived or user-mode processes that naturally disappear between scans.
    # Missing from pslist simply means they finished — NOT a rootkit.
    TRANSIENT_NAME_FRAGMENTS = [
        'chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave',
        'updater', 'update', 'installer', 'setup', 'msiexec',
        'tiworker', 'trustedinstaller', 'wuauclt', 'wusa',
        'mpsigstub', 'am_delta', 'mpcmdrun', 'mpdefender',
        'backgroundtransfer', 'backgroundtran',
        'searchindexer', 'searchprotocol', 'searchfilterhost',
        'runtimebroker', 'applicationframehost', 'shellexperiencehost',
        'startmenuexperiencehost', 'sihost', 'ctfmon', 'audiodg',
        'smartscreen', 'securityhealthservice', 'sgrmbroker',
        'microsoftedgeupdate', 'googleupdate', 'msmpeng',
        'onedrive', 'onedriveupdater',                  # OneDrive sync client
        'taskhostw', 'taskhost',                        # Task scheduler host (terminates after task)
        'werfault', 'werhelper',                        # Windows Error Reporting
        'dllhost', 'regsvr32',                          # COM surrogate / registration (short-lived)
        'wscript', 'cscript',                           # Script hosts
        'powershell', 'pwsh', 'cmd',                    # Shell processes
        'notepad', 'wordpad', 'mspaint',                # Lightweight user apps
    ]

    findings = []
    for r in rows:
        try:
            if r.get("pslist","").lower() != "false":
                continue
            if not (r.get("psscan","").lower() == "true" or
                    r.get("thrdscan","").lower() == "true" or
                    r.get("csrss","").lower() == "true"):
                continue

            name = (r.get("Name","") or "").lower().strip()

            # Known persistent system process hidden → definite DKOM, always flag
            if name in PERSISTENT_SYSTEM_PROCESSES:
                findings.append({
                    "pid": r.get("PID",""),
                    "name": r.get("Name",""),
                    "pslist_present": r.get("pslist",""),
                    "psscan_present": r.get("psscan",""),
                    "thrdscan_present": r.get("thrdscan",""),
                    "csrss_present": r.get("csrss",""),
                    "reason": "persistent_system_process_hidden_from_pslist",
                })
                continue

            # Known transient / user process → suppress (just terminated normally)
            if any(frag in name for frag in TRANSIENT_NAME_FRAGMENTS):
                continue

            # Unknown process absent from pslist → flag but note lower confidence
            findings.append({
                "pid": r.get("PID",""),
                "name": r.get("Name",""),
                "pslist_present": r.get("pslist",""),
                "psscan_present": r.get("psscan",""),
                "thrdscan_present": r.get("thrdscan",""),
                "csrss_present": r.get("csrss",""),
                "reason": "unknown_process_absent_from_pslist",
            })
        except Exception:
            pass
    return findings

def eng_suspicious_connection(rows, baseline):
    log.debug(f"eng_suspicious_connection: Received {len(rows)} rows.")
    allow_cidrs = baseline.get("network", {}).get("allow_cidrs", []) or []
    allow_ports = set(str(p) for p in (baseline.get("network", {}).get("allow_ports", []) or []))
    findings = []
    for r in rows:
        faddr = r.get("ForeignAddr","") or r.get("ForeignIP","")
        fport = r.get("ForeignPort","") or r.get("ForeignPortNumber","")
        if not faddr or faddr in ("0.0.0.0","::","*"):
            continue
        ok_cidr = in_cidrs(faddr, allow_cidrs)
        ok_port = str(fport) in allow_ports
        log.debug(f"Suspicious_connection check for {faddr}:{fport}. OK CIDR: {ok_cidr}, OK Port: {ok_port}")
        if not (ok_cidr or ok_port):
            findings.append({
                "pid": r.get("PID",""),
                "owner": r.get("Owner","") or r.get("Process",""),
                "ForeignAddr": faddr,
                "ForeignPort": fport,
                "LocalAddr": r.get("LocalAddr",""),
                "LocalPort": r.get("LocalPort",""),
                "State": r.get("State",""),
            })
    log.debug(f"eng_suspicious_connection: Found {len(findings)} findings.")
    return findings

def eng_network_enrichment_master(netstat_rows: List[Dict[str, Any]], detection_rules: List[Dict[str, Any]], baseline: Dict[str, Any], api_key: str) -> List[Dict[str, Any]]:
    findings = []
    processed_ips = {}
    if not netstat_rows:
        log.debug("eng_network_enrichment_master: Received no rows.")
        return findings
    log.info("Running network enrichment master engine...")
    allow_cidrs = baseline.get("network", {}).get("allow_cidrs", []) or []
    unique_ips_to_process = set()
    for row in netstat_rows:
        foreign_ip = row.get("ForeignAddr", "").strip()
        try:
            ip_obj = ipaddress.ip_address(foreign_ip)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_private:
                continue
            if not in_cidrs(foreign_ip, allow_cidrs):
                unique_ips_to_process.add(foreign_ip)
        except ValueError:
            continue
    log.debug(f"eng_network_enrichment_master: Unique IPs to process: {unique_ips_to_process}")
    for ip in unique_ips_to_process:
        if ip in processed_ips:
            enriched_data = processed_ips[ip]
        else:
            log.info(f"Fetching enrichment for IP: {ip}")
            enriched_data = get_ip_info(ip, api_key)
            processed_ips[ip] = enriched_data
        
    for ip, enriched_data in processed_ips.items():
        for detection_rule in detection_rules:
            if detection_rule.get('engine') != 'network_enrichment':
                continue
            is_suspicious_for_this_rule = False
            reasons = []
            rules_logic = detection_rule.get("logic", [])
            for logic_rule in rules_logic:
                rule_matched_locally = True
                for match_criteria in logic_rule.get("match", []):
                    field = match_criteria.get("field")
                    value = match_criteria.get("value")
                    operator = match_criteria.get("operator", "==")
                    if field in enriched_data:
                        data_val = enriched_data[field]
                        if operator == "==":
                            if not (str(data_val).lower() == str(value).lower()):
                                rule_matched_locally = False
                                break
                        elif operator == "<":
                            try:
                                if not (float(data_val) < float(value)):
                                    rule_matched_locally = False
                                    break
                            except ValueError:
                                rule_matched_locally = False
                                break
                if rule_matched_locally:
                    is_suspicious_for_this_rule = True
                    for match_criteria in logic_rule.get("match", []):
                        field = match_criteria.get("field")
                        if field in enriched_data:
                            reasons.append(f"Field '{field}' ({enriched_data[field]}) matches condition '{match_criteria.get('value')}'")
                    break
            if is_suspicious_for_this_rule:
                associated_connections = [conn for conn in netstat_rows if (conn.get("ForeignAddr", "") or conn.get("ForeignIP", "")) == ip]
                pids = list(set([c.get("Pid", c.get("PID", "N/A")) for c in associated_connections]))
                owners = list(set([c.get("Owner", c.get("Process", "N/A")) for c in associated_connections]))
                pids_display = ", ".join(p for p in pids if p and p != "N/A") or "N/A"
                owners_display = ", ".join(o for o in owners if o and o != "N/A") or "N/A"
                finding_evidence = {
                    "pid": pids_display, "owner": owners_display, "ip": ip,
                    "country": enriched_data.get("country", "N/A"), "isp": enriched_data.get("isp", "N/A"),
                    "reputation": enriched_data.get("reputation", "N/A"), "notes": "; ".join(reasons)
                }
                findings.append({
                    "id": detection_rule["id"], "title": detection_rule["title"], "narrative": detection_rule["narrative"],
                    "mitre": detection_rule.get("mitre", []), "weight": detection_rule["weight"],
                    "evidence": [finding_evidence]
                })
    return findings


def eng_suspicious_port_activity(rows, suspicious_ports: List[int]):
    findings = []
    susp_ports = {str(p) for p in suspicious_ports}
    for r in rows:
        local_port = r.get("LocalPort", "")
        foreign_port = r.get("ForeignPort", "")
        if (local_port and str(local_port).strip() != '0' and local_port in susp_ports) or \
           (foreign_port and str(foreign_port).strip() != '0' and foreign_port in susp_ports):
            findings.append({
                "pid": r.get("PID",""), "owner": r.get("Owner","") or r.get("Process",""),
                "Proto": r.get("Proto",""), "LocalPort": local_port,
                "ForeignPort": foreign_port, "Notes": "Connection found on a known suspicious port."
            })
    return findings

def eng_correlated_findings(all_findings: List[Dict[str, Any]], correlation_pairs: List[Any]):
    findings = []
    for pair in correlation_pairs:
        # Support both formats:
        #   Original YAML: ["rule_a", "rule_b"]  (2-element list)
        #   Dict format:   {primary_ids: [...], secondary_ids: [...]}
        if isinstance(pair, list) and len(pair) == 2:
            primary_ids = {pair[0]}
            secondary_ids = {pair[1]}
        elif isinstance(pair, dict):
            primary_ids = set(pair.get("primary_ids", []))
            secondary_ids = set(pair.get("secondary_ids", []))
        else:
            continue
        primary_pids = set()
        secondary_pids = set()
        for f in all_findings:
            if f['id'] in primary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        primary_pids.add(str(pid))
        for f in all_findings:
            if f['id'] in secondary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        secondary_pids.add(str(pid))
        correlated_pids = primary_pids.intersection(secondary_pids)
        if correlated_pids:
            for pid in sorted(list(correlated_pids)):
                correlated_info = []
                for f in all_findings:
                    if f['id'] in (primary_ids | secondary_ids):
                        pid_evidence = [ev for ev in f.get('evidence', []) if (ev.get('pid') == pid or ev.get('requestor_pid') == pid)]
                        if pid_evidence:
                            correlated_info.append({
                                "finding_id": f['id'], "title": f['title'], "evidence": pid_evidence,
                                "time_utc": f.get('time_utc', 'unknown')
                            })
                findings.append({
                    "correlated_pid": pid, "correlated_findings": correlated_info,
                    "correlated_rule_ids": list(primary_ids | secondary_ids),
                })
    return findings


def eng_malfind_injection(text, keywords: List[str]):
    findings = []
    if not text.strip(): return findings
    blocks = text.splitlines()
    acc = []
    for line in blocks:
        if line.strip(): acc.append(line)
    if not acc: return findings
    blob = "\n".join(acc)
    matches = re.finditer(r"^PID:\s*(\d+).*?Process:\s*([^\s]+).*?Start:\s*([0-9xa-fA-F]+).*?Protection:\s*([^\r\n]+)", blob, re.I|re.M|re.S)
    for m in matches:
        item = {
            "pid": m.group(1), "process": m.group(2), "Start": m.group(3),
            "Protection": m.group(4).strip(), "PrivateMemory": "", "Notes": ""
        }
        if keywords:
            kblob = blob[max(0, m.start()-400): m.end()+400]
            for kw in keywords:
                if re.search(kw, kblob, re.I):
                    item["Notes"] = f"Keyword hit: {kw}"
                    break
        findings.append(item)
    return findings

def eng_hollowed_process(text, keywords: List[str]):
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Hollowed" in line or "hollow" in line.lower():
            row = {"Details": line.strip()}
            if keywords:
                for kw in keywords:
                    if re.search(kw, line, re.I):
                        row["Details"] += f" [kw:{kw}]"
                        break
            findings.append(row)
    return findings

def eng_ldr_unlinked_module(text, temp_like_paths: List[str]):
    findings = []
    if not text.strip(): return findings

    # Windows Defender and certain AV/VM products use custom DLL loaders that
    # bypass the standard PEB module lists — they appear "unlinked" but are
    # completely legitimate. Suppress these known-good path fragments.
    DEFENDER_SAFE_PATHS = [
        'programdata/microsoft/windows defender',
        'program files/windows defender',
        'programdata/microsoft/windows defender advanced threat protection',
        'program files/oracle/virtualbox guest additions',
        'program files/vmware/vmware tools',
        'windows/system32/mrt.exe',
        'programdata/microsoft/windows security health',
        'windows/system32/securityhealthservice.exe',
    ]

    def _normalize(s):
        """Normalize any backslash variant to forward slash for matching."""
        s = s.lower()
        s = s.replace("\\\\", "/")
        s = s.replace("\\", "/")
        s = s.replace("//", "/")
        return s

    rx_temp = compile_any_contains_to_regex(temp_like_paths) if temp_like_paths else None
    for line in text.splitlines():
        low = line.lower()
        flag = ("false" in low and ("inload" in low or "ininit" in low or "inmem" in low))
        if not flag and rx_temp:
            flag = bool(rx_temp.search(low))
        if flag:
            # Suppress known-good paths before flagging
            line_norm = _normalize(line)
            if any(safe in line_norm for safe in DEFENDER_SAFE_PATHS):
                continue
            findings.append({"Details": line.strip()})
    return findings

def eng_handles_general(text, access_regex: str, target_regex: str = None, lsass_special=False):
    findings = []
    if not text.strip(): return findings
    re_access = re.compile(access_regex, re.I) if access_regex else None
    re_target = re.compile(target_regex, re.I) if target_regex else None
    for line in text.splitlines():
        low = line.lower()
        if re_access and not re_access.search(low): continue
        if re_target and not re_target.search(low): continue
        m = re.search(r"(?i)PID\s+(\d+).*?(?i)Process\s+([^\s]+)", line)
        req_pid = m.group(1) if m else ""
        req_name = m.group(2) if m else ""
        tgt = ""
        if "lsass" in low: tgt = "lsass.exe"
        findings.append({
            "requestor_pid": req_pid, "requestor_name": req_name, "target_pid": "",
            "target_name": tgt, "GrantedAccess": line.strip()
        })
    return findings

def eng_services_suspicious(rows: List[Dict[str, str]], temp_like_paths: List[str], baseline) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not temp_like_paths:
        return findings

    rx = compile_any_contains_to_regex(temp_like_paths)
    allowlist = baseline.get('service_path_allowlist', [])
    
    for r in rows:
        image_path = r.get("ImagePath", "")
        service_name = r.get("ServiceName", "")
        
        is_allowed = False
        for entry in allowlist:
            if entry.get('service_name') == service_name:
                regex = entry.get('image_path_regex')
                if regex and re.search(regex, image_path, re.I):
                    is_allowed = True
                    break
        
        if not is_allowed and image_path and rx.search(image_path.lower()):
            findings.append({
                "ServiceName": service_name, "ServiceType": r.get("Type", "N/A"),
                "ImagePath": image_path, "Start": r.get("Start", "N/A"), "Pid": r.get("Pid", "N/A")
            })
    return findings

def eng_scheduled_tasks(text, temp_like_paths: List[str], risky_exts: List[str]):
    findings = []
    if not text.strip(): return findings
    rx_path = compile_any_contains_to_regex(temp_like_paths) if temp_like_paths else None
    rx_ext  = re.compile(r"\.(" + "|".join([re.escape(e) for e in risky_exts]) + r")(\.|$)", re.I) if risky_exts else None
    for line in text.splitlines():
        low = line.lower()
        if (rx_path and rx_path.search(low)) or (rx_ext and rx_ext.search(low)):
            findings.append({"TaskLine": line.strip()})
    return findings

def eng_filescan_path_match(text, any_path_contains: List[str], any_file_ext: List[str], any_name_contains: List[str], baseline: Dict[str, Any]):
    findings = []
    if not text.strip(): return findings
    rx_path = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    rx_names = compile_any_contains_to_regex(any_name_contains) if any_name_contains else None
    rx_ext = None
    if any_file_ext:
        rx_ext = re.compile(r"\.(" + "|".join([re.escape(e) for e in any_file_ext]) + r")(\.|$)", re.I)

    allowlist = baseline.get('file_path_allowlist', [])

    for line in text.splitlines():
        low = line.lower()
        hit = False
        is_allowed = False
        
        m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(.*)$", line.strip())
        path = m.group(2) if m else line.strip()
        
        for entry in allowlist:
            regex = entry.get('path_regex')
            if regex and re.search(regex, path, re.I):
                is_allowed = True
                break
        
        if not is_allowed:
            if rx_path and rx_path.search(low): hit = True
            if rx_names and rx_names.search(low): hit = True
            if rx_ext and rx_ext.search(low): hit = True

        if hit:
            # Suppress known-good paths (Defender custom loader, VM tools, etc.)
            # Normalize all backslash variants → forward slash for reliable matching
            path_norm = path.lower()
            path_norm = path_norm.replace("\\\\", "/")  # double backslash first
            path_norm = path_norm.replace("\\", "/")    # then single backslash
            path_norm = path_norm.replace("//", "/")    # collapse doubles
            if any(safe in path_norm for safe in DEFENDER_SAFE_PATHS):
                continue
            findings.append({"Offset": m.group(1) if m else "", "Path": path})
    return findings


def eng_registry_printkey_matches(vol, image, outdir, keys: List[str], value_regex: str, baseline: Dict[str, Any]):
    findings = []
    rx = re.compile(value_regex, re.I) if value_regex else None
    
    # We don't have a specific registry allowlist, so we just run the check.

    for key in keys:
        plugin_name = "windows.registry.printkey"
        cmd_args = [vol, "-f", image, "--quiet", plugin_name, "--key", key]
        rc, out = sh(cmd_args)

        safe_key_name = re.sub(r"[^A-Za-z0-9]+", "_", key)
        artifact_path = outdir / "artifacts" / f"{plugin_name.replace('.', '_')}_{safe_key_name}.txt"
        write_file(artifact_path, out)

        if not rx or not out.strip():
            continue
        for line in out.splitlines():
            if rx.search(line):
                m = re.match(r'^\s*([0-9a-fA-F]+)\s+(\w+)\s+([^\s]+)\s+(.*)$', line.strip())
                if m:
                    offset, name, type_val, decoded = m.groups()
                    findings.append({
                        "Key": key, "Name": name.strip(), "Type": type_val.strip(),
                        "Decoded": decoded.strip()
                    })
                else:
                    findings.append({"Key": key, "Name": "", "Decoded": line.strip()})
    return findings


def eng_userassist_suspicious(text, any_path_contains: List[str]):
    findings = []
    if not text.strip(): return findings
    rx = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    for line in text.splitlines():
        low = line.lower()
        if rx and rx.search(low):
            path_match = re.search(r'\\??\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)
            guid_path_match = re.search(r'\{[0-9A-F-]+\}\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)
            extracted_path = ""
            if path_match: extracted_path = path_match.group(1).strip()
            elif guid_path_match: extracted_path = guid_path_match.group(1).strip()
            count_match = re.search(r'Count:\s*(\d+)', line)
            last_updated_match = re.search(r'Last Updated:\s*(.*)', line)
            findings.append({
                "Path": extracted_path if extracted_path else line.strip(),
                "Count": count_match.group(1) if count_match else "",
                "LastUpdated": last_updated_match.group(1) if last_updated_match else ""
            })
    return findings

def eng_unusual_parent_child(pslist_rows, detections_params, baseline):
    bypid = {r.get("PID",""): {"name": r.get("ImageFileName","") or r.get("Name",""), "path": r.get("Path","")} for r in pslist_rows}
    findings = []
    known_good_parents = set(detections_params.get("known_good_parents", []))
    child_process_name = detections_params.get("child_process")
    
    allowlist = baseline.get('parent_child_allowlist', [])

    for r in pslist_rows:
        pid = r.get("PID","")
        name = r.get("ImageFileName","") or r.get("Name","")
        ppid = r.get("PPID","")
        parent_info = bypid.get(ppid, {})
        parent_name = parent_info.get("name", "")
        
        if name.lower() == child_process_name.lower():
            if parent_name.lower() not in [p.lower() for p in known_good_parents]:
                
                is_allowed = False
                for entry in allowlist:
                    p_regex = entry.get('parent_process_regex')
                    p_name = entry.get('parent_process_name')
                    c_regex = entry.get('child_process_regex')
                    c_name = entry.get('child_process_name')
                    
                    if p_regex and re.search(p_regex, parent_name, re.I) and c_regex and re.search(c_regex, name, re.I):
                        is_allowed = True
                        break
                    if p_name and p_name.lower() == parent_name.lower() and c_name and c_name.lower() == name.lower():
                        is_allowed = True
                        break

                if not is_allowed:
                    findings.append({
                        "parent_name": parent_name, "parent_pid": ppid,
                        "child_name": name, "child_pid": pid,
                        "command_line": r.get("CommandLine", "") # pslist might not have this, cmdline does
                    })
    return findings

def eng_sessions_anomalous(rows, ignore_users: List[str], suspicious_auth_packages: List[str]):
    findings = []
    ign = set([u.lower() for u in ignore_users or []])
    sap = [s.lower() for s in suspicious_auth_packages or []]
    for r in rows:
        user = (r.get("User","") or r.get("Username","")).lower()
        if user and user not in ign:
            auth = (r.get("AuthPackage","") or r.get("AuthenticationPackage","")).lower()
            if auth in sap:
                findings.append({
                    "SessionId": r.get("SessionId",""), "User": r.get("User",""),
                    "AuthPackage": r.get("AuthPackage",""), "LogonType": r.get("LogonType",""),
                    "Pid": r.get("Pid","") or r.get("PID",""), "Process": r.get("Process","") or r.get("ImageFileName",""),
                })
    return findings

def eng_suspicious_cmdline(cmdline_rows: List[Dict[str, str]], suspicious_keywords: List[str], baseline: Dict[str, Any]):
    findings = []
    if not cmdline_rows or not suspicious_keywords: return findings
    rx = compile_any_contains_to_regex(suspicious_keywords)
    allowlist = baseline.get('command_line_allowlist', [])

    for r in cmdline_rows:
        pid = r.get("PID", "")
        # Volatility 3 windows.cmdline uses 'Process' and 'Args' columns
        name = r.get("Process", "") or r.get("ImageFileName", "") or r.get("Name", "")
        cmdline = r.get("Args", "") or r.get("CommandLine", "") or r.get("Cmdline", "")

        is_allowed = False
        for entry in allowlist:
            if 'regex' in entry and re.search(entry['regex'], cmdline, re.I):
                is_allowed = True
                break
            if 'exact' in entry and entry['exact'] == cmdline:
                is_allowed = True
                break
            if 'process_name' in entry and entry['process_name'].lower() == name.lower() and \
               'contains' in entry and entry['contains'].lower() in cmdline.lower():
                is_allowed = True
                break
        
        if not is_allowed and cmdline and rx.search(cmdline):
            findings.append({"pid": pid, "name": name, "command_line": cmdline})
    return findings

def eng_bash_history_grep(text: str, suspicious_keywords: List[str]):
    findings = []
    if not text.strip() or not suspicious_keywords: return findings
    rx = compile_any_contains_to_regex(suspicious_keywords)
    current_user = "Unknown"
    for line in text.splitlines():
        user_match = re.match(r'^\s*User:\s*(.+)$', line, re.IGNORECASE)
        if user_match:
            current_user = user_match.group(1).strip()
            continue
        command_match = re.match(r'^\s*Command:\s*(.+)$', line, re.IGNORECASE)
        if command_match: command = command_match.group(1).strip()
        else: command = line.strip()
        if command and rx.search(command):
            findings.append({"User": current_user, "Command": command})
    return findings

def eng_exec_from_tmp(pslist_rows: List[Dict[str, str]], temp_like_paths: List[str], cmdline_rows: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Detect processes whose image path is in a temporary or user-writable directory."""
    findings = []
    if not temp_like_paths:
        return findings

    # Known-good processes that legitimately run from ProgramData or similar paths
    EXEC_TMP_WHITELIST = {
        # Windows Defender
        'msmpeng.exe', 'mpdefendercoreservice.exe', 'mpdefendercore',
        'mpcmdrun.exe', 'mpsigstub.exe', 'nissrv.exe', 'mrt.exe',
        'sgrmbroker.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe',
        # VM tools
        'vgauthservice.exe', 'vmtoolsd.exe', 'vm3dservice.exe',
        # Forensic/capture tools
        'mrcv120.exe', 'mrcv110.exe', 'mrcv130.exe', 'winpmem.exe',
        'dumplt.exe', 'rammap.exe', 'procdump.exe',
        # Windows Search
        'searchprotocolhost.exe', 'searchprotocol', 'searchfilterhost.exe',
        'searchindexer.exe',
        # Windows system
        'audiodg.exe', 'backgroundtaskhost.exe', 'runtimebroker.exe',
        'sihclient.exe', 'musnotification.exe', 'wuauclt.exe',
        'tiworker.exe', 'trustedinstaller.exe', 'wusa.exe',
        'cleanmgr.exe', 'dismhost.exe',
    }

    rx = compile_any_contains_to_regex(temp_like_paths)
    seen_pids = set()

    # Check cmdline rows first — has full path in Args column
    for r in (cmdline_rows or []):
        pid  = str(r.get("PID", ""))
        name = (r.get("Process", "") or r.get("ImageFileName", "") or r.get("Name", "")).strip()
        args = r.get("Args", "") or r.get("CommandLine", "") or ""
        if not args or not name:
            continue
        if name.lower().rstrip() in EXEC_TMP_WHITELIST:
            continue
        if rx.search(args.lower()) and pid not in seen_pids:
            seen_pids.add(pid)
            findings.append({
                "pid": pid,
                "name": name,
                "path": args[:150],
                "Notes": "Process command line references a temporary or user-writable directory."
            })

    # Also check pslist
    for r in (pslist_rows or []):
        path = r.get("ImageFileName", "") or r.get("Name", "") or r.get("Path", "")
        pid  = str(r.get("PID", ""))
        name = (r.get("ImageFileName", "") or r.get("Name", "")).strip()
        if not path or not name:
            continue
        if name.lower().rstrip() in EXEC_TMP_WHITELIST:
            continue
        if rx.search(path.lower()) and pid not in seen_pids:
            seen_pids.add(pid)
            findings.append({
                "pid": pid,
                "name": name,
                "path": path,
                "Notes": "Process image executed from a temporary or user-writable directory."
            })
    return findings


def eng_windows_ssdt_hooks(text, allowed_modules_regex: str):
    findings = []
    if not text.strip(): return findings
    rx_allowed = re.compile(allowed_modules_regex, re.I)
    for line in text.splitlines():
        if "Hooked" in line and not rx_allowed.search(line):
            m = re.search(r"Owner:\s*([^\s]+)", line)
            owner = m.group(1) if m else "unknown"
            findings.append({"Details": line.strip(), "OwnerModule": owner, "Notes": "SSDT Hook detected outside of allowed kernel modules."})
    return findings

def eng_windows_callbacks_suspicious(text, known_good_modules_regex: str):
    findings = []
    if not text.strip(): return findings
    rx_known_good = re.compile(known_good_modules_regex, re.I)
    for line in text.splitlines():
        if "Callback" in line and not rx_known_good.search(line):
            m = re.search(r"Owner:\s*([^\s]+)", line)
            owner = m.group(1) if m else "unknown"
            findings.append({"Details": line.strip(), "OwnerModule": owner, "Notes": "Unexpected callback owner detected."})
    return findings

def eng_iat_redirection(text: str) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip():
        return findings
    for line in text.splitlines():
        if "Non-Module" in line or "Private" in line or "Heap" in line:
            m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?Function:\s*([^\s]+).*?Resolved To:\s*(.*)', line, re.I)
            if m:
                pid, proc, func, resolved = m.groups()
                findings.append({
                    "pid": pid, "process": proc, "Function": func,
                    "ResolvedTo": resolved, "Notes": "IAT entry points to non-module memory."
                })
    return findings

def eng_vad_private_rx(text: str, require_executable: bool) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip():
        return findings
    for line in text.splitlines():
        if "RWX" in line or "RX" in line or "EXECUTE" in line:
            if require_executable:
                if "Private" in line or "Image" not in line:
                    m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?Start:\s*([^\s]+).*?Protection:\s*([^\s]+).*?Tag:\s*([^\s]+)', line, re.I)
                    if m:
                        pid, proc, start, prot, tag = m.groups()
                        findings.append({
                            "pid": pid, "process": proc, "Start": start, "Protection": prot, "Tag": tag, "Notes": "VAD region with executable permissions detected."
                        })
    return findings

def eng_threads_start_outside_module(text: str) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Start address outside module" in line:
            m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?TID:\s*(\d+).*?Start:\s*([^\s]+).*?Module:\s*([^\r\n]+)', line, re.I)
            if m:
                pid, proc, tid, start_addr, module = m.groups()
                findings.append({
                    "pid": pid, "process": proc, "ThreadId": tid,
                    "StartAddress": start_addr, "ModuleAtStart": module.strip(), "Notes": "Thread starts in unmapped memory or outside a known module."
                })
    return findings

def eng_netscan_beacon_like(rows: List[Dict[str, str]], suspicious_process_regex: str) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not suspicious_process_regex: return findings
    rx_proc = re.compile(suspicious_process_regex, re.I)
    for r in rows:
        owner = r.get("Owner", "") or r.get("Process", "")
        faddr = r.get("ForeignAddr", "")
        fport = r.get("ForeignPort", "")
        state = r.get("State", "")
        if rx_proc.search(owner) and faddr not in ["127.0.0.1", "0.0.0.0"] and state == "ESTABLISHED":
            findings.append({
                "pid": r.get("PID", ""), "owner": owner, "LocalAddr": r.get("LocalAddr", ""),
                "LocalPort": r.get("LocalPort", ""), "ForeignAddr": faddr, "ForeignPort": fport,
                "State": state, "Notes": "Beacon-like connection from a suspicious process."
            })
    return findings

def eng_verinfo_mismatch(rows: List[Dict[str, str]], system_dir_regex: str) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not system_dir_regex: return findings
    rx_sysdir = re.compile(system_dir_regex, re.I)
    for r in rows:
        path = r.get("Path", "")
        name = r.get("FileDescription", "") or r.get("ProductName", "")
        if rx_sysdir.search(path) and not name:
            findings.append({
                "pid": r.get("PID", ""), "process": r.get("ImageFileName", ""),
                "Path": path, "Notes": "System file with missing version info."
            })
        if name and not re.search(re.escape(name), path, re.I):
            findings.append({
                "pid": r.get("PID", ""), "process": r.get("ImageFileName", ""),
                "Path": path, "CompanyName": r.get("CompanyName", ""),
                "ProductName": r.get("ProductName", ""), "FileDescription": r.get("FileDescription", ""),
                "Notes": "Version info and file path mismatch."
            })
    return findings

def eng_strings_ioc_match(text: str, patterns: List[str]) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip() or not patterns: return findings
    
    current_pid = None
    current_process = None
    
    for line in text.splitlines():
        pid_match = re.match(r'^-+ PID: (\d+), Process: (.+)$', line)
        if pid_match:
            current_pid = pid_match.group(1)
            current_process = pid_match.group(2)
            continue
        
        for pattern in patterns:
            if re.search(pattern, line):
                findings.append({
                    "pid": current_pid, "process": current_process,
                    "Offset": "unknown", "String": line.strip()
                })
                break
    return findings

def eng_modules_vs_modscan_diff(modules_text: str, modscan_text: str):
    findings = []
    if not modules_text.strip() or not modscan_text.strip(): return findings
    modules_info = {}
    for line in modules_text.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 2:
            modules_info[parts[1].lower()] = {"Base": parts[0]}

    modscan_info = {}
    for line in modscan_text.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 2:
            modscan_info[parts[1].lower()] = {"Base": parts[0]}

    hidden = modscan_info.keys() - modules_info.keys()

    for h in hidden:
        findings.append({
            "Module": h, "Base": modscan_info[h]["Base"], "Notes": "Hidden kernel module detected by modscan."
        })
    return findings

def eng_registry_getcellroutine_hook(text: str):
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Hooked" in line:
            m = re.search(r"Owner:\s*([^\s]+)", line)
            hook_target = m.group(1).strip() if m else "unknown"
            m = re.search(r'Hive:\s*([^\s]+)', line)
            hive = m.group(1).strip() if m else "unknown"
            findings.append({
                "Hive": hive, "Status": "Hooked", "HookTarget": hook_target, "Notes": "Registry hive's GetCellRoutine is hooked."
            })
    return findings

def eng_registry_orphan_hives(hivelist_text: str, hivescan_text: str):
    findings = []
    if not hivelist_text.strip() or not hivescan_text.strip(): return findings
    hivelist = {re.split(r'\s+', l.strip())[-1].lower() for l in hivelist_text.splitlines() if l.strip()}
    hivescan = {re.split(r'\s+', l.strip())[-1].lower() for l in hivescan_text.splitlines() if l.strip()}
    orphans = hivescan - hivelist
    for o in orphans:
        findings.append({"HivePath": o, "PresentInList": "False", "Notes": "Orphaned registry hive detected."})
    return findings

def eng_statistics_baseline_anomaly(text: str, baseline: Dict[str, Any]):
    findings = []
    if not text.strip(): return findings
    stats = kv_parse(text)
    expected_ranges = baseline.get("statistics_ranges", {})
    for metric, value in stats.items():
        if metric in expected_ranges:
            try:
                val = int(value)
                min_val, max_val = expected_ranges[metric]['min'], expected_ranges[metric]['max']
                if not (min_val <= val <= max_val):
                    findings.append({
                        "Metric": metric, "Value": value,
                        "ExpectedRange": f"{min_val}-{max_val}",
                        "Notes": "Metric value outside of expected baseline range."
                    })
            except (ValueError, TypeError):
                continue
    return findings


# ---------------------------
# HTML report
# ---------------------------



def _row_get(r: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = r.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def _extract_path_from_cmdline(cmd: str) -> str:
    if not cmd:
        return ""
    s = cmd.strip()
    if s.startswith('"'):
        m = re.match(r'^"([A-Za-z]:\[^"]+?\[^"]+?\.exe)"', s, re.I)
        if m:
            return m.group(1)
    m = re.match(r'^([A-Za-z]:\[^\s]+?\.exe)', s, re.I)
    return m.group(1) if m else ""


def _build_path_map(dlllist_rows: List[Dict[str, Any]]) -> Dict[str, str]:
    """Extract PID -> executable path from windows.dlllist.
    The executable itself appears as the first entry (or the entry whose
    BaseDllName/FileName matches the process ImageFileName).
    We keep the first Path seen per PID that ends in .exe.
    """
    path_map: Dict[str, str] = {}
    for r in dlllist_rows:
        pid = _row_get(r, 'PID', 'Pid')
        if not pid or pid in path_map:
            continue
        p = _row_get(r, 'Path', 'MappedPath', 'FullName')
        if p and p.lower().endswith('.exe'):
            path_map[pid] = p
    return path_map


def _merge_process_context(pslist_rows: List[Dict[str, Any]],
                           cmdline_rows: List[Dict[str, Any]] = None,
                           path_map: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """Merge pslist + cmdline + optional path_map (from dlllist).
    Handles both Vol3 column names: 'Args' and 'CommandLine'.
    """
    cmdline_rows = cmdline_rows or []
    path_map = path_map or {}

    cmd_by_pid: Dict[str, Dict] = {}
    for r in cmdline_rows:
        pid = _row_get(r, 'PID', 'Pid')
        if pid:
            cmd_by_pid[pid] = r

    merged = []
    for r in pslist_rows:
        pid = _row_get(r, 'PID', 'Pid')
        c = cmd_by_pid.get(pid, {})
        name = _row_get(r, 'ImageFileName', 'Name', 'Process') or _row_get(c, 'ImageFileName', 'Name', 'Process', 'Process')

        # Vol3 windows.cmdline uses 'Args'; other plugins use 'CommandLine'
        cmd = (_row_get(r, 'CommandLine') or
               _row_get(c, 'CommandLine') or
               _row_get(c, 'Args'))

        # Path priority: dlllist map > pslist field > cmdline extraction
        path = (path_map.get(pid) or
                _row_get(r, 'Path', 'ImagePathName', 'ExecutablePath') or
                _extract_path_from_cmdline(cmd))

        merged.append({
            'PID': pid,
            'PPID': _row_get(r, 'PPID', 'ParentPID', 'InheritedFromUniqueProcessId'),
            'ImageFileName': name,
            'CommandLine': cmd,
            'Path': path,
            '_raw': r,
        })
    return merged


def _levenshtein(a: str, b: str) -> int:
    a, b = a or '', b or ''
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j-1] + 1
            dele = prev[j] + 1
            rep = prev[j-1] + (0 if ca == cb else 1)
            cur.append(min(ins, dele, rep))
        prev = cur
    return prev[-1]


def eng_masquerade_wrong_path(pslist_rows, cmdline_rows, params, baseline, path_map=None):
    findings = []
    known = {x.lower() for x in (params.get('known_system_processes') or [])}
    allowed_paths = [x.lower() for x in (params.get('allowed_paths') or [])]
    suspicious_paths = [x.lower() for x in (params.get('suspicious_paths') or [])]
    merged = _merge_process_context(pslist_rows, cmdline_rows, path_map)
    proc_wl = {p.lower() for p in (baseline.get('process_whitelist', {}).get('windows', []) or [])}
    for r in merged:
        name = (r.get('ImageFileName') or '').lower()
        if not name or name not in known:
            continue
        if name in proc_wl:
            continue
        raw_p = r.get('Path') or ''
        if not raw_p:
            continue
        is_allowed = _path_allowed(raw_p, allowed_paths)
        looks_userw = any(sp in _fwd(raw_p) for sp in [_fwd(x) for x in suspicious_paths])
        if not is_allowed:
            findings.append({
                'pid': r.get('PID',''), 'name': r.get('ImageFileName',''), 'path': r.get('Path',''),
                'command_line': r.get('CommandLine',''), 'reason': 'system_process_name_in_non_standard_path',
                'user_writable_hint': looks_userw,
            })
    return findings


def eng_masquerade_typosquat(pslist_rows, params, baseline):
    findings = []
    known = [x.lower() for x in (params.get('known_system_processes') or [])]
    thr = int(params.get('fuzzy_threshold', 2))
    proc_wl = {p.lower() for p in (baseline.get('process_whitelist', {}).get('windows', []) or [])}

    TYPOSQUAT_SUPPRESS = {
        'sc.exe', 'at.exe', 'net.exe', 'cmd.exe', 'reg.exe', 'wsl.exe',
        'mmc.exe', 'csc.exe', 'ftp.exe', 'arp.exe', 'ssh.exe', 'tar.exe',
        'clip.exe', 'curl.exe', 'more.exe', 'sort.exe', 'find.exe',
        'comp.exe', 'tree.exe', 'help.exe', 'sihost.exe',
    }

    # Legitimate short-name Windows tools that fuzzy-match system process names
    # but are NOT masquerading — suppress these to avoid false positives
    TYPOSQUAT_SUPPRESS = {
        'sc.exe',        # Service Control — 2 chars from lsm.exe
        'at.exe',        # Task scheduler legacy
        'fs.exe',        # File system tools
        'net.exe',       # Net commands
        'cmd.exe',       # Command prompt
        'reg.exe',       # Registry editor
        'wsl.exe',       # Windows Subsystem for Linux
        'mmc.exe',       # Microsoft Management Console
        'csc.exe',       # C# compiler
        'wsl.exe',       # WSL
        'ftp.exe',       # FTP client
        'arp.exe',       # ARP tool
        'nbt.exe',       # NBT stat
        'ssh.exe',       # SSH client
        'tar.exe',       # Tar tool
        'clip.exe',      # Clipboard tool
        'curl.exe',      # Curl
        'more.exe',      # More pager
        'sort.exe',      # Sort tool
        'find.exe',      # Find tool
        'comp.exe',      # File compare
        'tree.exe',      # Directory tree
        'type.exe',      # Type command
        'help.exe',      # Help
        'mode.com',      # Mode command
        'sihost.exe',    # Shell input host — legitimate Windows process
    }
    for r in pslist_rows:
        raw_name = (_row_get(r, 'ImageFileName', 'Name', 'Process') or '')
        # Normalize Unicode lookalikes (Cyrillic 'е' -> 'e', etc.) before fuzzy compare
        name = unicodedata.normalize('NFKD', raw_name).encode('ascii', 'ignore').decode().lower()
        if not name or name in proc_wl or name in known:
            continue
        if name in TYPOSQUAT_SUPPRESS:
            continue
        if not name.endswith('.exe'):
            continue
        best, dist = None, 999
        for legit in known:
            d = _levenshtein(name, legit)
            if d < dist:
                best, dist = legit, d
        if best is not None and 0 < dist <= thr:
            findings.append({'pid': _row_get(r,'PID','Pid'), 'name': _row_get(r,'ImageFileName','Name','Process'), 'looks_like': best, 'distance': dist, 'path': _row_get(r,'Path','ImagePathName')})
    return findings


def _fwd(p: str) -> str:
    """Normalize a Windows path to lowercase forward-slashes for reliable substring matching."""
    if not p:
        return ''
    lp = p.lower()
    # Normalize device/SystemRoot prefixes
    lp = lp.replace('\\systemroot\\', 'c:/windows/')
    lp = lp.replace('/systemroot/', 'c:/windows/')
    # Strip \\??\\ and \??\ device notation
    lp = re.sub(r'^[\\/]+\?+[\\/]+', '', lp)
    # Strip \Device\HarddiskVolumeN\ prefix -> bare path
    lp = re.sub(r'^\\?device\\harddiskvolume\d+\\', '/', lp)
    # Normalize all backslashes to forward
    lp = lp.replace('\\', '/')
    # Collapse double slashes
    lp = re.sub(r'/+', '/', lp)
    return lp


def _path_has_dir(p: str) -> bool:
    """Return True if path contains a directory component (not just a bare filename)."""
    return ('/' in p.replace('\\', '/').strip('/')) or (':' in p)


def _path_allowed(raw_path: str, allowed_path_patterns: List[str]) -> bool:
    """
    Check if raw_path is within one of the allowed path patterns.
    - Returns True (allowed) if path has no directory info (cannot confirm it's suspicious)
    - Returns True if any allowed pattern is a substring of the normalized path
    - Returns False only when a full directory path is present AND none match
    """
    if not raw_path:
        return True  # Unknown path → don't flag
    norm = _fwd(raw_path)
    if not _path_has_dir(norm):
        return True  # Bare filename like 'svchost.exe' → cannot determine → skip
    norm_pats = [_fwd(ap) for ap in allowed_path_patterns]
    return any(ap in norm for ap in norm_pats)


def eng_masquerade_svchost_no_k(pslist_rows, cmdline_rows, params, path_map=None):
    """Fire ONLY when cmdline is actually available AND -k is missing,
    OR when path is available AND it is NOT in an allowed location.
    Skips entirely when cmdline is empty (Volatility could not read it).
    """
    findings = []
    proc_name = (params.get('process_name') or 'svchost.exe').lower()
    req = (params.get('required_cmdline_contains') or '-k ').lower()
    allowed_paths = [x.lower() for x in (params.get('allowed_paths') or [])]
    for r in _merge_process_context(pslist_rows, cmdline_rows, path_map):
        name = (r.get('ImageFileName') or '').lower()
        if name != proc_name:
            continue
        raw_cmd = (r.get('CommandLine') or '').strip()
        raw_path = (r.get('Path') or '').strip()
        cmd = raw_cmd.lower()
        # Condition A: cmdline is known and -k is absent
        # Vol3 outputs '-' or '\x00' when cmdline is unreadable
        _cmd_real = raw_cmd if raw_cmd not in ('', '-', '\x00') else ''
        cmd_available = bool(_cmd_real)
        missing_k = cmd_available and (req not in _cmd_real.lower())

        # Condition B: path is known AND is in a clearly non-standard location
        wrong_path = not _path_allowed(raw_path, allowed_paths)

        # Only fire if we have at least one CONFIRMED condition
        if missing_k or wrong_path:
            findings.append({
                'pid': r.get('PID',''),
                'name': r.get('ImageFileName',''),
                'path': raw_path if raw_path else '(path unavailable)',
                'command_line': raw_cmd if raw_cmd else '(cmdline unavailable)',
                'missing_required_flag': 'YES' if missing_k else 'NO',
                'path_not_allowed': 'YES' if wrong_path else 'NO',
            })
    return findings


def eng_masquerade_boot_chain(pslist_rows, params):
    rows = _merge_process_context(pslist_rows, [])
    bypid = {str(r.get('PID','')): r for r in rows}
    relationships = params.get('enforced_relationships') or []
    findings = []

    # smss.exe self-terminates after spawning winlogon.exe / csrss.exe on every
    # Windows version. Its PID will be absent from a live memory dump — this is
    # completely normal. When the missing parent is one of these self-terminating
    # processes, suppress the finding instead of showing "Unknown parent".
    self_terminating_parents = {'smss.exe'}

    for rel in relationships:
        child = (rel.get('child') or '').lower()
        allowed = {p.lower() for p in (rel.get('allowed_parents') or [])}
        for r in rows:
            nm = (r.get('ImageFileName') or '').lower()
            if nm != child:
                continue
            ppid = str(r.get('PPID',''))
            parent_entry = bypid.get(ppid, {})
            parent_name = (parent_entry.get('ImageFileName') or '').lower()

            if parent_name in allowed:
                continue  # Correct parent — OK

            # Parent PID not in process list at all.
            # If the expected parent is known to self-terminate (smss.exe),
            # its absence is expected — do NOT flag it.
            if not parent_name and allowed & self_terminating_parents:
                continue

            # Real mismatch: parent is present but is the wrong process
            # Skip if actual parent is a legitimate system process (VM/hypervisor artifact)
            # These occur in VMs where the boot chain differs slightly
            VM_BOOT_SUPPRESSIONS = {
                'svchost.exe', 'services.exe', 'system', 'registry',
                'vmtoolsd.exe', 'vgauthservice.exe',
            }
            if parent_name and parent_name in VM_BOOT_SUPPRESSIONS:
                continue
            VM_BOOT_SUPPRESSIONS = {'svchost.exe','services.exe','system','registry','vmtoolsd.exe','vgauthservice.exe'}
            if parent_name and parent_name in VM_BOOT_SUPPRESSIONS:
                continue
            display_parent = parent_entry.get('ImageFileName') or f'(exited process, PID {ppid})'
            findings.append({
                'child_pid': r.get('PID',''),
                'child_name': r.get('ImageFileName',''),
                'parent_pid': ppid,
                'parent_name': display_parent,
                'expected_parents': sorted(allowed),
            })
    return findings


def eng_masquerade_explorer(pslist_rows, cmdline_rows, params, path_map=None):
    findings = []
    target = (params.get('process_name') or 'explorer.exe').lower()
    allowed_paths = [x.lower() for x in (params.get('allowed_paths') or [])]
    for r in _merge_process_context(pslist_rows, cmdline_rows, path_map):
        name = (r.get('ImageFileName') or '').lower()
        if name != target:
            continue
        path = (r.get('Path') or '').lower()
        if path and not _path_allowed(path, allowed_paths):
            findings.append({'pid': r.get('PID',''), 'name': r.get('ImageFileName',''), 'path': r.get('Path',''), 'command_line': r.get('CommandLine','')})
    return findings


def eng_masquerade_unicode_padding(pslist_rows, params):
    findings = []
    check_trailing_space = bool(params.get('check_trailing_space', True))
    invisible = ['​', '‌', '‍', '﻿', '⁠']
    for r in pslist_rows:
        raw_name = str(r.get('ImageFileName', r.get('Name', '')))
        if not raw_name:
            continue
        reason = None
        if check_trailing_space and raw_name != raw_name.rstrip(' '):
            reason = 'trailing_space'
        elif any(ch in raw_name for ch in invisible):
            reason = 'zero_width_unicode'
        elif any(ord(ch) < 32 for ch in raw_name):
            reason = 'control_character'
        if reason:
            findings.append({'pid': _row_get(r,'PID','Pid'), 'name_repr': repr(raw_name), 'reason': reason})
    return findings


def eng_shell_spawned_by_office_or_browser(pslist_rows, params, baseline):
    rows = _merge_process_context(pslist_rows, [])
    bypid = {str(r.get('PID','')): r for r in rows}
    children = {x.lower() for x in (params.get('child_processes') or [])}
    parents = {x.lower() for x in (params.get('suspicious_parents') or [])}
    allow_pc = baseline.get('parent_child_allowlist', []) or []
    findings = []
    for r in rows:
        child = (r.get('ImageFileName') or '').lower()
        if child not in children:
            continue
        ppid = str(r.get('PPID',''))
        pnm = (bypid.get(ppid,{}).get('ImageFileName') or '').lower()
        if pnm not in parents:
            continue
        allowed = False
        for a in allow_pc:
            if a.get('parent_process_name','').lower() == pnm and a.get('child_process_name','').lower() == child:
                allowed = True; break
        if allowed:
            continue
        findings.append({'child_pid': r.get('PID',''), 'child_name': r.get('ImageFileName',''), 'parent_pid': ppid, 'parent_name': bypid.get(ppid,{}).get('ImageFileName',''), 'command_line': r.get('CommandLine','')})
    return findings

def html_escape(s: str) -> str:
    """HTML-escape using stdlib for correctness (handles all edge cases)."""
    return _html.escape(str(s or ""), quote=True)

def render_html_evidence(finding_id: str, evidence: List[Dict[str, Any]]) -> str:
    if not evidence: return "No key evidence."
    if finding_id == "suspicious_cmdline_args":
        display_items = [f"PID **{html_escape(r['pid'])}**: `{html_escape(r['command_line'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "registry_run_key_persistence":
        display_items = []
        for r in evidence[:3]:
            key_name = r.get("Key", "N/A").split("\\")[-1]
            entry_name = r.get("Name", "N/A")
            decoded_val = r.get("Decoded", "N/A")
            display_items.append(f"Key: **{html_escape(key_name)}** - Entry: `{html_escape(entry_name)}` - Value: `{html_escape(decoded_val)}`")
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious Run Key entries:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "unknown_process_name":
        display_items = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])}" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "unusual_parent_child":
        display_items = [f"Child: `{html_escape(r['child_name'])}` (PID: {html_escape(r['child_pid'])}) spawned by Parent: `{html_escape(r['parent_name'])}` (PPID: {html_escape(r['parent_pid'])})" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Unusual parent-child process chains:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "services_suspicious":
        display_items = [f"Service: `{html_escape(r['ServiceName'])}` (Type: {html_escape(r.get('ServiceType', 'N/A'))}) running from `{html_escape(r['ImagePath'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious services detected:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "scheduled_tasks_suspicious":
        display_items = [f"Task: `{html_escape(r['TaskLine'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious scheduled tasks:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "psxview_hidden":
        critical_processes = ["lsass.exe", "services.exe", "winlogon.exe"]
        critical_evidence = [r for r in evidence if r.get('name') in critical_processes]
        lines = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])} (pslist: {html_escape(r.get('pslist_present',''))}, psscan: {html_escape(r.get('psscan_present',''))})" for r in critical_evidence]
        if len(lines) > 0:
            summary = f"<p>Total **{len(evidence)}** hidden processes. Examples showing process list mismatches (found by ProcSentinel):</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
        else:
            summary = f"<p>Total **{len(evidence)}** hidden processes identified, showing discrepancies across process lists (found by ProcSentinel).</p>"
        return summary
    if finding_id == "filescan_suspicious_names":
        relevant_paths = []
        for r in evidence:
            path = r.get('Path', '').lower()
            if "demon.py.txt" in path or "dumpit.exe" in path:
                relevant_paths.append(r.get('Path'))
            elif "catroot" not in path and "system32" not in path and "program files" not in path:
                relevant_paths.append(r.get('Path'))
        unique_paths = list(set(relevant_paths))
        deleted_paths = [p for p in unique_paths if "(deleted)" in p.lower()]
        other_paths = [p for p in unique_paths if "(deleted)" not in p.lower()]
        display_lines = []
        if deleted_paths:
            display_lines.append(f"<b>Deleted files still in memory:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in deleted_paths[:2]])
        if other_paths and len(display_lines) < 3:
            display_lines.append(f"<b>Other suspicious paths:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in other_paths[:(3 - len(display_lines))]])
        if len(unique_paths) > 3:
            display_lines.append(f"...and {len(unique_paths)-len(display_lines) + (2 if deleted_paths else 0)} more.")
        if not display_lines: return f"<p>Suspicious files found: See full details in raw artifacts.</p>"
        return f"<p>Suspicious files found:</p><ul>{''.join(f'<li>{item}</li>' for item in display_lines)}</ul>"
    if finding_id == "registry_recentdocs_py_exe":
        decoded_paths = []
        for r in evidence:
            if r.get('Decoded'):
                decoded_paths.append(r['Decoded'])
        lines = [f"File: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3: lines.append(f"...and {len(decoded_paths)-3} more.")
        return f"<p>Accessed files:</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
    if finding_id == "userassist_suspicious":
        # FIX: The display_items variable needs to be initialized here.
        display_items = []
        decoded_paths = []
        for r in evidence:
            clean_path = Path(r.get('Path', '')).name
            if clean_path: decoded_paths.append(clean_path)
        lines = [f"Program: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3: lines.append(f"...and {len(decoded_paths)-3} more.")
        return f"<p>GUI-launched programs:</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
    if finding_id == "ldr_unlinked_module":
        details = evidence[0].get("Details", "")
        m = re.search(r"(\d+)\s+([^\s]+)\s+.*?(True|False)\s+(True|False)\s+(True|False)\s+(.*)", details)
        if m:
            pid, name, inload, ininit, inmem, path = m.groups()
            return f"<p>Process: **{html_escape(name)}** (PID: {html_escape(pid)})<br>Path: `{html_escape(path)}`<br>InLoad: {html_escape(inload)}, InInit: {html_escape(ininit)}, InMem: {html_escape(inmem)}</p>"
        return f"<pre style=\"white-space:pre-wrap;margin:0\">{html_escape(json.dumps(evidence[0], ensure_ascii=False, indent=2))}</pre>"
    if finding_id == "suspicious_network_enrichment":
        table_rows = ""
        network_evidence_list = evidence 
        for r in network_evidence_list:
            reputation_color = "#EF4444" if r.get('reputation') == "Malicious" else \
                               "#F59E0B" if r.get('reputation') == "Suspicious" else \
                               "#34D399" if r.get('reputation') == "Clean" else "#9CA3AF"
            table_rows += f"""
<tr>
  <td>{html_escape(r.get('pid', 'N/A'))}</td>
  <td>{html_escape(r.get('owner', 'N/A'))}</td>
  <td>{html_escape(r.get('ip', 'N/A'))}</td>
  <td>{html_escape(r.get('country', 'N/A'))}</td>
  <td>{html_escape(r.get('isp', 'N/A'))}</td>
  <td style="color: {reputation_color}; font-weight: bold;">{html_escape(r.get('reputation', 'N/A'))}</td>
</tr>"""
        return f"""
<p>Malicious IPs identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">PID</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Owner</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">IP</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Country</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">ISP</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Reputation</th></tr>
  {table_rows}
</table>"""
    if finding_id == "suspicious_port_activity":
        table_rows = ""
        for r in evidence:
            local_port_display = html_escape(r['LocalPort']) if r.get('LocalPort') and str(r['LocalPort']).strip() != '0' else 'N/A'
            foreign_port_display = html_escape(r['ForeignPort']) if r.get('ForeignPort') and str(r['ForeignPort']).strip() != '0' else 'N/A'
            table_rows += f"""
<tr>
  <td>{html_escape(r['pid'])}</td>
  <td>{html_escape(r['owner'])}</td>
  <td>{html_escape(r['Proto'])}</td>
  <td>{local_port_display}</td>
  <td>{foreign_port_display}</td>
</tr>"""
        return f"""
<p>Connections on suspicious ports identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>PID</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Owner</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Proto</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Local Port</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Foreign Port</th></tr>
  {table_rows}
</table>"""
    if finding_id == "bash_history_suspicious":
        display_items = [f"User: **{html_escape(r['User'])}** - Command: `{html_escape(r['Command'])}`" for r in evidence[:5]]
        if len(evidence) > 5: display_items.append(f"...and {len(evidence)-5} more.")
        return f"<p>Suspicious commands found in Bash history:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id.startswith("correlation"):
        correlated_pids = evidence[0].get("correlated_pid", "N/A")
        correlated_info = evidence[0].get("correlated_findings", [])
        details_html = ""
        for info in correlated_info:
            details_html += f"<li><b>{html_escape(info.get('title'))}:</b> {html_escape(json.dumps(info.get('evidence'), ensure_ascii=False))}</li>"
        return f"<p>Correlated PID: <b>{html_escape(correlated_pids)}</b></p><ul>{details_html}</ul>"
    if finding_id == "dumpit_present":
        paths = [r.get('Path', 'N/A') for r in evidence]
        unique_paths = list(set(paths))
        if unique_paths:
            return f"<p>Acquisition tool(s) found: <ul>{''.join([f'<li>`{html_escape(p)}`</li>' for p in unique_paths[:3]])}</ul></p>"
        else:
            return f"<p>Memory acquisition tool present in memory. See raw artifacts for details.</p>"
    if finding_id == "kernel_callbacks_suspicious":
        return f"<p>Found **{len(evidence)}** suspicious kernel callbacks. See raw artifacts for details.</p>"
    if finding_id == "modules_hidden_vs_modscan":
        return f"<p>Found **{len(evidence)}** hidden kernel modules. See raw artifacts for details.</p>"
    if finding_id == "registry_orphan_hives":
        return f"<p>Found **{len(evidence)}** orphaned registry hives. See raw artifacts for details.</p>"
    
    if len(evidence) == 1:
        return f"<pre style='white-space:pre-wrap;margin:0'>{html_escape(json.dumps(evidence[0], ensure_ascii=False, indent=2))}</pre>"
    else:
        return f"<p>Multiple evidence items. See raw artifacts for full details.</p>"


def render_html_explanation(finding_id: str, finding: Dict[str, Any], detections_config: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    original_narrative = "No specific narrative available for this finding."
    # First check if the finding itself carries a narrative (network enrichment findings do)
    if finding.get('narrative'):
        original_narrative = finding['narrative']
    else:
        for os_profile in detections_config.get('os_profiles', {}).values():
            for rule in os_profile.get('detections', []):
                if rule.get('id') == finding_id:
                    original_narrative = rule.get('narrative', original_narrative)
                    break
            if original_narrative != "No specific narrative available for this finding.": break
    if finding_id == "suspicious_port_activity":
        is_local_only = True
        allow_cidrs = baseline_config.get("network", {}).get("allow_cidrs", []) or []
        for ev_item in finding.get('evidence', []):
            foreign_addr = ev_item.get('ForeignAddr', '').strip() or ev_item.get('ip', '').strip()
            if foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                is_local_only = False
                break
            if (foreign_addr in ["0.0.0.0", "127.0.0.1", "::"] or in_cidrs(foreign_addr, allow_cidrs)) and not ev_item.get('ForeignPort'):
                 is_local_only = True
            if ev_item.get('LocalPort') and ev_item.get('ForeignPort') and foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                 is_local_only = False
                 break
        if is_local_only:
            return "A process was observed communicating or listening on a port that is commonly associated with unusual internal services or local debugging activity. While unusual, this does not directly indicate external command and control (C2) communication unless coupled with further evidence of external connections."
    return original_narrative

def render_html(case: str, profile: str, score_sum: int, band: str, findings: List[Dict[str, Any]], detections_config: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    sorted_findings = sorted(findings, key=lambda f: int(f.get('weight', 0)), reverse=True)

    def sev_label(w: int) -> str:
        w = int(w or 0)
        if w >= 90: return 'Critical'
        if w >= 75: return 'High'
        if w >= 45: return 'Medium'
        return 'Low'

    sev_counts = {'Critical':0,'High':0,'Medium':0,'Low':0}
    mitre_count: Dict[str,int] = {}
    for f in sorted_findings:
        sev_counts[sev_label(int(f.get('weight',0)))] += 1
        for t in (f.get('mitre') or []):
            mitre_count[t] = mitre_count.get(t, 0) + 1

    def _mitre_url(tid: str) -> str:
        parts = tid.split('.')
        return 'https://attack.mitre.org/techniques/' + '/'.join(parts) + '/'
    mitre_badges = ''.join([
        f'<a href="{_mitre_url(t)}" target="_blank" rel="noopener" class="mitre">{html_escape(t)} <small>x{c}</small></a>'
        for t, c in sorted(mitre_count.items(), key=lambda x: (-x[1], x[0]))
    ]) or '<span class="muted">No MITRE mappings</span>'

    narrative_items = []
    for f in sorted_findings[:8]:
        narrative = render_html_explanation(f.get('id',''), f, detections_config, baseline_config)
        narrative_items.append(f"<li><b>{html_escape(f.get('title', f.get('id','')))}</b> — {html_escape(narrative)}</li>")
    if not narrative_items:
        narrative_items.append('<li>No significant findings were detected. If this is unexpected, verify plugin outputs, command-line/path fields, and enabled rules.</li>')

    table_rows = []
    for idx, f in enumerate(sorted_findings, 1):
        weight = int(f.get('weight', 0))
        sev = sev_label(weight)
        sev_cls = sev.lower()
        mitre = ''.join([f'<span class="mitre">{html_escape(x)}</span>' for x in (f.get('mitre') or [])]) or '<span class="muted">None</span>'
        evidence_html = render_html_evidence(f.get('id',''), f.get('evidence', []))
        explanation_html = html_escape(render_html_explanation(f.get('id',''), f, detections_config, baseline_config))
        table_rows.append(f"""
        <tr>
          <td>{idx}</td>
          <td><div class='f-title'>{html_escape(f.get('title',''))}</div><div class='muted'>{html_escape(f.get('id',''))}</div></td>
          <td><span class='sev {sev_cls}'>{sev}</span> <span class='score'>{weight}</span></td>
          <td>{mitre}</td>
          <td><details><summary>View evidence ({len(f.get('evidence', []) or [])})</summary><div class='evidence-wrap'>{evidence_html}</div></details></td>
          <td>{explanation_html}</td>
        </tr>""")
    table_html = ''.join(table_rows) if table_rows else "<tr><td colspan='6'>No findings</td></tr>"

    generated = now_iso()
    return f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>ProcSentinel Report - {html_escape(case)}</title>
<style>
:root{{--bg:#060b12;--panel:#0b1220;--panel2:#0f172a;--text:#e5f0ff;--muted:#94a3b8;--blue:#38bdf8;--line:#1e293b;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;}}
*{{box-sizing:border-box}}
body{{margin:0;background:radial-gradient(circle at 10% 0%, #0a1d3a 0%, var(--bg) 40%),var(--bg);color:var(--text);font-family:Inter,Segoe UI,Roboto,Arial,sans-serif}}
.container{{max-width:1450px;margin:0 auto;padding:20px}}
.header{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:16px;padding:18px;border:1px solid #12304f;background:linear-gradient(180deg,#081122,#07101a);border-radius:16px;box-shadow:0 0 0 1px rgba(56,189,248,.08) inset, 0 20px 60px rgba(0,0,0,.35)}}
.title h1{{margin:0;font-size:28px;letter-spacing:.4px}}
.title .sub{{margin-top:6px;color:var(--muted)}}
.badge{{display:inline-block;padding:6px 10px;border:1px solid #1f3c58;border-radius:999px;background:#091321;color:#c8eaff;font-weight:600}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}}
.card{{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:14px;padding:14px}}
.card h3{{margin:0 0 10px;font-size:13px;color:#b7c8dd;font-weight:600;text-transform:uppercase;letter-spacing:.08em}}
.metric{{font-size:28px;font-weight:700}}
.muted{{color:var(--muted);font-size:12px}}
.panel{{background:linear-gradient(180deg,#08111f,#090f1a);border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px}}
.panel h2{{margin:0 0 12px;font-size:18px}}
ul{{margin:0;padding-left:18px}} li{{margin:6px 0}}
.mitre{{display:inline-block;margin:2px;padding:4px 8px;border-radius:999px;border:1px solid #174f73;background:#081828;color:#bdeafe;font-size:12px}}
.sev{{display:inline-block;padding:4px 8px;border-radius:999px;font-weight:700;font-size:12px;border:1px solid transparent;min-width:66px;text-align:center}}
.sev.critical{{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.45);color:#fecaca}}
.sev.high{{background:rgba(249,115,22,.12);border-color:rgba(249,115,22,.45);color:#fed7aa}}
.sev.medium{{background:rgba(234,179,8,.12);border-color:rgba(234,179,8,.45);color:#fef08a}}
.sev.low{{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.45);color:#bbf7d0}}
.score{{color:#cfe8ff;font-weight:700;margin-left:6px}}
.table-wrap{{overflow:auto;border-radius:12px;border:1px solid var(--line)}}
table{{width:100%;border-collapse:collapse;min-width:1100px;background:#070d16}}
th,td{{padding:10px 10px;border-bottom:1px solid #142033;vertical-align:top;font-size:13px}}
th{{text-align:left;color:#a7d9ff;background:#081322;position:sticky;top:0;z-index:1}}
tr:hover td{{background:#08101c}}
.f-title{{font-weight:700;color:#eaf6ff;margin-bottom:4px}}
details{{background:#060c15;border:1px solid #15243a;border-radius:8px;padding:6px}}
summary{{cursor:pointer;color:#9fdcff;font-weight:600}}
.evidence-wrap{{margin-top:8px;max-width:520px}}
.evidence-wrap pre{{white-space:pre-wrap;word-break:break-word}}
.footer{{margin-top:12px;color:var(--muted);font-size:12px}}
@media (max-width:1200px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div class='title'>
      <h1>ProcSentinel Memory Forensics Report</h1>
      <div class='sub'>Case <b>{html_escape(case)}</b> · Profile <b>{html_escape(profile)}</b> · Generated {html_escape(generated)}</div>
    </div>
    <div>
      <div class='badge'>Severity: {html_escape(band)}</div>
    </div>
  </div>

  <div class='grid'>
    <div class='card'><h3>Total Score</h3><div class='metric'>{score_sum}</div><div class='muted'>Aggregated weighted score</div></div>
    <div class='card'><h3>Total Findings</h3><div class='metric'>{len(sorted_findings)}</div><div class='muted'>All detections + correlations</div></div>
    <div class='card'><h3>Critical / High</h3><div class='metric'>{sev_counts['Critical']} / {sev_counts['High']}</div><div class='muted'>Priority triage queue</div></div>
    <div class='card'><h3>Medium / Low</h3><div class='metric'>{sev_counts['Medium']} / {sev_counts['Low']}</div><div class='muted'>Context + supporting hits</div></div>
    <div class='card'><h3>MITRE Techniques</h3><div class='metric'>{len(mitre_count)}</div><div class='muted'>Unique ATT&CK mappings</div></div>
  </div>

  <div class='panel'>
    <h2>Executive Narrative</h2>
    <ul>{''.join(narrative_items)}</ul>
  </div>

  <div class='panel'>
    <h2>MITRE ATT&CK Mapping</h2>
    <div>{mitre_badges}</div>
  </div>

  <div class='panel'>
    <h2>Detailed Findings</h2>
    <div class='table-wrap'>
      <table>
        <thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>MITRE</th><th>Evidence</th><th>Explanation</th></tr></thead>
        <tbody>{table_html}</tbody>
      </table>
    </div>
    <div class='footer'>Raw plugin outputs remain in the artifacts directory. If findings are unexpectedly empty, verify that Volatility plugins produced CSV/text content and that process path/command-line fields are available.</div>
  </div>
</div>
</body>
</html>"""


# ---------------------------
# Main
# ---------------------------

def main():
    log.debug("Main function started.")
    ap = argparse.ArgumentParser(description="Volatility detections CLI")
    ap.add_argument("--image", required=True, help="Memory image path (e.g., memory.raw)")
    ap.add_argument("--case", default="case1")
    ap.add_argument("--detections", default="detections.yaml")
    ap.add_argument("--baseline", default="baseline.yaml")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--api-key", default="", help="AbuseIPDB key. Prefer env var ABUSEIPDB_KEY (safer than CLI arg).")
    ap.add_argument('--save-raw', action='store_true', help='Compatibility flag')
    ap.add_argument('--verbose', action='store_true', help='Compatibility flag')
    args = ap.parse_args()
    # Prefer env var — CLI args are visible in ps aux
    if not args.api_key:
        args.api_key = os.environ.get("ABUSEIPDB_KEY", "")

    if getattr(args, "verbose", False):
        log.debug("Compatibility flags: --verbose enabled")
    if getattr(args, "save_raw", False):
        log.debug("Compatibility flags: --save-raw enabled (artifacts are already persisted)")
    log.debug("Arguments parsed successfully.")

    outdir = Path(args.outdir) / args.case
    ensure_dirs(outdir)

    detections_config_path = Path(args.detections)
    if not detections_config_path.exists():
        log.error(f"Error: Detections file not found at {detections_config_path}")
        sys.exit(1)
    log.debug(f"Loading detections from: {detections_config_path}")
    det = yaml.safe_load(detections_config_path.read_text())
    log.debug(f"Detections config loaded: {json.dumps(det, indent=2)[:500]}...")

    baseline_config_path = Path(args.baseline)
    if not baseline_config_path.exists():
        log.error(f"Error: Baseline file not found at {baseline_config_path}")
        sys.exit(1)
    log.debug(f"Loading baseline from: {baseline_config_path}")
    base = yaml.safe_load(baseline_config_path.read_text())
    log.debug(f"Baseline config loaded: {json.dumps(base, indent=2)[:500]}...")

    vol = find_vol_binary(det.get("volatility", {}).get("v3_binaries", ["vol","volatility3"]))
    if not vol:
        log.error("Neither volatility3 nor vol found on PATH")
        sys.exit(3)
    log.debug(f"Volatility binary found: {vol}")

    info_txt = run_plugin(vol, args.image, "windows.info", "text", outdir)
    oskey = detect_os(info_txt)
    log.info(f"Detected OS profile: {oskey}")
    os_prof = (det.get("os_profiles", {}).get(oskey, {}))
    plugins = os_prof.get("plugins", [])
    cache_outputs: Dict[str, Any] = {}

    for p in plugins:
        name = p["name"]
        fmt  = p.get("format","text")
        fallbacks = p.get("fallback", [])
        log.info(f"[+] [+] Running plugin: {name} (fmt={fmt})")
        used, content = try_plugin_with_fallbacks(vol, args.image, name, fmt, fallbacks, outdir)
        cache_outputs[used] = {"format": fmt, "content": content}
        if used != name:
            log.info(f"Fallback used: {used}")
        if content:
            log.debug(f"Captured content for {used} (first 200 chars):\n{content[:200]}...")
        else:
            log.debug(f"Captured content for {used} is EMPTY or None.")

    # Auto-run windows.strings if strings_sensitive_iocs rule is enabled but plugin not in list
    detections_cfg_check = os_prof.get("detections", [])
    needs_strings = any(r.get("id") == "strings_sensitive_iocs" and r.get("enabled", True) for r in detections_cfg_check)
    plugin_names_in_list = {p["name"] for p in plugins}
    strings_plugin = "windows.strings" if oskey == "windows" else f"{oskey}.strings"
    if needs_strings and strings_plugin not in cache_outputs and strings_plugin not in plugin_names_in_list:
        log.info(f"[+] [+] Auto-running plugin: {strings_plugin} (required by strings_sensitive_iocs rule)")
        used, content = try_plugin_with_fallbacks(vol, args.image, strings_plugin, "text", [], outdir)
        cache_outputs[used] = {"format": "text", "content": content}
        if content:
            log.debug(f"Captured content for {used} (first 200 chars):\n{content[:200]}...")
        else:
            log.debug(f"{strings_plugin} output is EMPTY or None.")

    def get_csv(name):
        content_info = cache_outputs.get(name, {})
        # Also try fallback-cached entries (e.g. netscan cached under netscan key)
        if not content_info:
            for k, v in cache_outputs.items():
                if k == name:
                    content_info = v
                    break
        if not content_info:
            return []
        content = content_info.get("content", "")
        if not content:
            return []
        # windows.cmdline outputs tab-separated text, not CSV
        # Parse into dicts with Process/PID/Args keys
        if name == "windows.cmdline":
            import io as _io2, csv as _csv2
            # Volatility 3 cmdline outputs CSV with a Volatility banner before headers
            # Find real header line: TreeDepth,PID,Process,Args
            lines = content.splitlines()
            header_idx = None
            for i, line in enumerate(lines):
                if "PID" in line and "Process" in line and "Args" in line:
                    header_idx = i
                    break
            if header_idx is not None:
                clean = "\n".join(lines[header_idx:])
                parsed = list(_csv2.DictReader(_io2.StringIO(clean)))
                result = []
                for r in parsed:
                    result.append({
                        "PID":           (r.get("PID") or "").strip(),
                        "Process":       (r.get("Process") or "").strip(),
                        "Args":          (r.get("Args") or "").strip(),
                        "ImageFileName": (r.get("Process") or "").strip(),
                        "CommandLine":   (r.get("Args") or "").strip(),
                        "Name":          (r.get("Process") or "").strip(),
                    })
                if result:
                    return result
        return parse_csv(content)

    def get_txt(name):
        content_info = cache_outputs.get(name, {})
        if not content_info:
            for k, v in cache_outputs.items():
                if k == name:
                    content_info = v
                    break
        if not content_info:
            return ""
        return content_info.get("content", "")

    detections_cfg = os_prof.get("detections", [])
    supported_rule_ids = {
        "unknown_process_name","psxview_hidden","suspicious_port_activity","suspicious_connection",
        "malfind_injection","hollowed_process","ldr_unlinked_module","handles_dangerous_access","handles_lsass_access",
        "services_suspicious","scheduled_tasks_suspicious","filescan_suspicious_names","dumpit_present",
        "registry_run_key_persistence","registry_recentdocs_py_exe","userassist_suspicious","unusual_parent_child",
        "sessions_anomalous","suspicious_cmdline_args","bash_history_suspicious","exec_from_tmp","ssdt_hooks_suspicious",
        "kernel_callbacks_suspicious","iat_redirection","vad_exec_private","threads_start_outside_module",
        "netscan_beacon_like","verinfo_mismatch","strings_sensitive_iocs","modules_hidden_vs_modscan",
        "registry_getcellroutine_hooked","registry_orphan_hives","statistics_profile_anomaly",
        "masquerade_wrong_path","masquerade_typosquat","masquerade_svchost_no_k","masquerade_boot_chain",
        "masquerade_explorer","masquerade_unicode_padding","shell_spawned_by_office_or_browser",
        "lolbin_execution","powershell_obfuscation","credential_dumping_cmdline",
        "security_tool_tampering","shadow_copy_deletion","winlogon_hijack",
        "unusual_parent_child","suspicious_port_activity","netscan_beacon_like",
        "registry_run_key_persistence","scheduled_tasks_suspicious","services_suspicious"
    }
    unsupported = [r.get('id') for r in detections_cfg if r.get('enabled', True) and not r.get('id','').startswith('correlation_') and r.get('engine') != 'network_enrichment' and r.get('id') not in supported_rule_ids]
    if unsupported:
        log.warning('[WARN] Enabled rules not implemented in runner:', ', '.join(sorted(unsupported)))
    findings = []
    score = 0

    for rule in detections_cfg:
        if not rule.get("enabled", True): continue
        rid, title, weight, mitre = rule["id"], rule.get("title", rule["id"]), int(rule.get("weight", 1)), rule.get("mitre", [])
        ev = []
        if rid.startswith("correlation_") or rule.get("engine") == "network_enrichment": continue
        log.info(f"Running detection engine: {rid}")
        try:
            if rid == "unknown_process_name":
                ps = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                ev = eng_unknown_process_name(ps, base, oskey)
            elif rid == "psxview_hidden":
                # Volatility 3 has no psxview plugin; cross-reference pslist vs psscan ourselves
                pslist_rows = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                psscan_rows = get_csv("windows.psscan") if oskey == "windows" else get_csv(f"{oskey}.psscan")
                pslist_pids = {str(r.get("PID","")).strip() for r in pslist_rows if r.get("PID")}
                synthetic_psxview = []
                for r in psscan_rows:
                    pid = str(r.get("PID","")).strip()
                    name = r.get("ImageFileName","") or r.get("Name","")
                    if not pid:
                        continue
                    in_pslist = pid in pslist_pids
                    synthetic_psxview.append({
                        "PID": pid,
                        "Name": name,
                        "pslist": "True" if in_pslist else "False",
                        "psscan": "True",
                        "thrdscan": "False",
                        "csrss": "False",
                    })
                ev = eng_psxview_hidden(synthetic_psxview)
            elif rid == "suspicious_port_activity":
                rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_suspicious_port_activity(rows, rule.get("params", {}).get("suspicious_ports", []))
            elif rid == "suspicious_connection":
                rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_suspicious_connection(rows, base)
            elif rid == "malfind_injection":
                text = get_txt("windows.malfind") if oskey == "windows" else get_txt(f"{oskey}.malfind")
                ev = eng_malfind_injection(text, rule.get("params", {}).get("keywords", []))
            elif rid == "hollowed_process":
                # windows.hollowprocesses is not a standard Vol3 plugin;
                # use malfind output which captures the same hollow/unmapped patterns
                hollow_txt = get_txt("windows.malfind") if oskey == "windows" else get_txt(f"{oskey}.malfind")
                ev = eng_hollowed_process(hollow_txt, rule.get("params", {}).get("keywords", []))
            elif rid == "ldr_unlinked_module":
                ev = eng_ldr_unlinked_module(get_txt("windows.ldrmodules"), rule.get("params", {}).get("temp_like_paths", []))
            elif rid == "handles_dangerous_access":
                ev = eng_handles_general(get_txt("windows.handles"), rule.get("params", {}).get("access_regex", ""))
            elif rid == "handles_lsass_access":
                ev = eng_handles_general(get_txt("windows.handles"), rule.get("params", {}).get("access_regex", ""), rule.get("params", {}).get("target_process_regex","(?i)^lsass\\.exe$"), True)
            elif rid == "services_suspicious":
                ev = eng_services_suspicious(get_csv("windows.svcscan"), rule.get("params", {}).get("temp_like_paths", []), base)
            elif rid == "scheduled_tasks_suspicious":
                text = get_txt("windows.scheduled_tasks") or get_txt("windows.registry.scheduled_tasks")
                ev = eng_scheduled_tasks(text, rule.get("params", {}).get("temp_like_paths", []), rule.get("params", {}).get("risky_exts", []))
            elif rid == "filescan_suspicious_names" or rid == "dumpit_present":
                text = get_txt("windows.filescan") if oskey=="windows" else get_txt(f"{oskey}.pagecache.Files")
                ev = eng_filescan_path_match(text, rule.get("params", {}).get("any_path_contains", []), rule.get("params", {}).get("any_file_ext", []), rule.get("params", {}).get("any_name_contains", []), base)
            elif rid == "registry_run_key_persistence" or rid == "registry_recentdocs_py_exe":
                ev = eng_registry_printkey_matches(vol, args.image, outdir, rule.get("params", {}).get("keys", []), rule.get("params", {}).get("value_regex", ""), base)
            elif rid == "userassist_suspicious":
                ev = eng_userassist_suspicious(get_txt("windows.registry.userassist"), rule.get("params", {}).get("any_path_contains", []))
            elif rid == "unusual_parent_child":
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                ev = eng_unusual_parent_child(ps, rule.get("params", {}), base)
            elif rid == "sessions_anomalous":
                rows = get_csv("windows.sessions")
                ev = eng_sessions_anomalous(rows, base.get("sessions",{}).get("ignore_users",[]), rule.get("params", {}).get("suspicious_auth_packages", []))
            elif rid == "suspicious_cmdline_args":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "lolbin_execution":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "powershell_obfuscation":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "credential_dumping_cmdline":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "security_tool_tampering":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "shadow_copy_deletion":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "winlogon_hijack":
                ev = eng_registry_printkey_matches(vol, args.image, outdir, rule.get("params", {}).get("keys", []), rule.get("params", {}).get("value_regex", ""), base)
            elif rid == "bash_history_suspicious":
                text = get_txt("linux.bash") if oskey == "linux" else get_txt("mac.bash")
                ev = eng_bash_history_grep(text, rule.get("params", {}).get("suspicious_keywords", []))
            elif rid == "exec_from_tmp":
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                ev = eng_exec_from_tmp(ps, rule.get("params", {}).get("temp_like_paths", []), get_csv("windows.cmdline"))
            elif rid == "masquerade_wrong_path":
                _pm = _build_path_map(get_csv("windows.dlllist"))
                ev = eng_masquerade_wrong_path(get_csv("windows.pslist"), get_csv("windows.cmdline"), rule.get("params", {}), base, _pm)
            elif rid == "masquerade_typosquat":
                ev = eng_masquerade_typosquat(get_csv("windows.pslist"), rule.get("params", {}), base)
            elif rid == "masquerade_svchost_no_k":
                _pm = _build_path_map(get_csv("windows.dlllist"))
                ev = eng_masquerade_svchost_no_k(get_csv("windows.pslist"), get_csv("windows.cmdline"), rule.get("params", {}), _pm)
            elif rid == "masquerade_boot_chain":
                ev = eng_masquerade_boot_chain(get_csv("windows.pslist"), rule.get("params", {}))
            elif rid == "masquerade_explorer":
                _pm = _build_path_map(get_csv("windows.dlllist"))
                ev = eng_masquerade_explorer(get_csv("windows.pslist"), get_csv("windows.cmdline"), rule.get("params", {}), _pm)
            elif rid == "masquerade_unicode_padding":
                ev = eng_masquerade_unicode_padding(get_csv("windows.pslist"), rule.get("params", {}))
            elif rid == "shell_spawned_by_office_or_browser":
                ev = eng_shell_spawned_by_office_or_browser(get_csv("windows.pslist"), rule.get("params", {}), base)
            # New Engines
            elif rid == "ssdt_hooks_suspicious":
                ev = eng_windows_ssdt_hooks(get_txt("windows.ssdt"), rule.get("params", {}).get("allowed_modules_regex", ""))
            elif rid == "kernel_callbacks_suspicious":
                ev = eng_windows_callbacks_suspicious(get_txt("windows.callbacks"), rule.get("params", {}).get("known_good_modules_regex", ""))
            elif rid == "iat_redirection":
                ev = eng_iat_redirection(get_txt("windows.iat"))
            elif rid == "vad_exec_private":
                ev = eng_vad_private_rx(get_txt("windows.vadinfo") or get_txt("windows.vadwalk"), rule.get("params", {}).get("require_executable", True))
            elif rid == "threads_start_outside_module":
                # windows.suspicious_threads is not standard Vol3; fall back to thrdscan text
                thr_txt = get_txt("windows.suspicious_threads") or get_txt("windows.thrdscan") or get_txt("windows.psscan")
                ev = eng_threads_start_outside_module(thr_txt)
            elif rid == "netscan_beacon_like":
                rows = get_csv("windows.netscan") or get_csv("windows.netstat")
                ev = eng_netscan_beacon_like(rows, rule.get("params", {}).get("suspicious_process_regex", ""))
            elif rid == "verinfo_mismatch":
                ev = eng_verinfo_mismatch(get_csv("windows.verinfo"), rule.get("params", {}).get("system_dir_regex", ""))
            elif rid == "strings_sensitive_iocs":
                text = get_txt("windows.strings")
                ev = eng_strings_ioc_match(text, rule.get("params", {}).get("patterns", []))
            elif rid == "modules_hidden_vs_modscan":
                ev = eng_modules_vs_modscan_diff(get_txt("windows.modules"), get_txt("windows.modscan"))
            elif rid == "registry_getcellroutine_hooked":
                ev = eng_registry_getcellroutine_hook(get_txt("windows.registry.getcellroutine"))
            elif rid == "registry_orphan_hives":
                ev = eng_registry_orphan_hives(get_txt("windows.registry.hivelist"), get_txt("windows.registry.hivescan"))
            elif rid == "statistics_profile_anomaly":
                ev = eng_statistics_baseline_anomaly(get_txt("windows.statistics"), base)

        except Exception as e:
            log.warning(f"Engine {rid} failed: {e}")
            traceback.print_exc(file=sys.stderr)
        
        if ev:
            findings.append({"id": rid, "title": title, "mitre": mitre, "weight": weight, "evidence": ev})
            score += weight
        log.info(f"Finished detection engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

    log.info(f"Running master network enrichment engine...")
    network_enrichment_rules = [r for r in detections_cfg if r.get("engine") == "network_enrichment" and r.get("enabled", True)]
    netstat_rows_for_master_engine = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
    network_findings = []
    if network_enrichment_rules and netstat_rows_for_master_engine:
        network_findings = eng_network_enrichment_master(netstat_rows_for_master_engine, network_enrichment_rules, base, args.api_key)
        for fnd in network_findings:
            findings.append(fnd)
            score += fnd["weight"]
    log.info(f"Finished master network enrichment engine. Current total score: {score}. Total network findings generated: {len(network_findings)}")


    log.info(f"Starting correlation analysis...")
    for rule in detections_cfg:
        if not rule.get("enabled", True): continue
        rid, title, weight, mitre = rule["id"], rule.get("title", rule["id"]), int(rule.get("weight", 1)), rule.get("mitre", [])
        ev = []
        if not rid.startswith("correlation_"): continue
        log.info(f"Running correlation engine: {rid}")
        try:
            ev = eng_correlated_findings(findings, rule.get("params", {}).get("correlation_pairs", []))
        except Exception as e:
            log.warning(f"Correlation engine {rid} failed: {e}")
            traceback.print_exc(file=sys.stderr)
        if ev:
            findings.append({"id": rid, "title": title, "mitre": mitre, "weight": weight, "evidence": ev})
            score += weight
        log.info(f"Finished correlation engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

    bands = (base.get("report", {}).get("severity_bands") or det.get("scoring", {}).get("severity_bands") or [])
    band_label = "Unknown"
    for band in bands:
        if score <= int(band["max"]):
            band_label = band["label"]
            break

    findings_path = outdir / "findings.jsonl"
    with findings_path.open("w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd, ensure_ascii=False) + "\n")

    log.info("\n=== SUMMARY ===")
    log.info(f"Score: {score}  => Severity: {band_label}")
    log.info(f"Raw artifacts: {outdir/'artifacts'}")
    log.info(f"Findings JSONL: {findings_path}")
    html_path = outdir / "report.html"
    write_file(html_path, render_html(args.case, oskey, score, band_label, findings, det, base))
    log.info(f"HTML report: {html_path}")

if __name__ == "__main__":
    main()
