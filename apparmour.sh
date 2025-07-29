#!/bin/bash

# ----------------------
# Banner Function
# ----------------------
print_banner() {
  local border="------------------------------------------------------------"
  echo "$border"
  printf "%*s\n" $(((${#border} + ${#1}) / 2)) "$1"
  echo "$border"
  echo
  echo "This script audits AppArmor profiles for security issues"
  echo "and generates HTML reports for findings against Security Best Practice and"
  echo "ISA/IEC 62443 compliance status."
  echo "$border"
}

print_banner "AppArmor Audit Script"

# Base directory for AppArmor profiles
PROFILE_BASE_DIR="./apparmor_profiles"

# Output files
OUTPUT_FILE="apparmor_audit_report.html"
COMPLIANCE_FILE="compliance_status.html"

# ----------------------
# Define findings
# ----------------------
declare -A FINDINGS

FINDINGS["AA001"]="capability dac_override|Bypass File Permissions|Critical|Involved|Remove 'capability dac_override' unless essential."
FINDINGS["AA002"]="capability ptrace|Memory Inspection via Ptrace|High|Planned|Avoid ptrace access. Remove unless debugging tools explicitly require it."
FINDINGS["AA003"]="capability net_admin|Network Configuration Control|High|Involved|Allow only if managing network interfaces."
FINDINGS["AA004"]="capability net_raw|Raw Network Access|High|Involved|Remove unless required for DHCP ping checks."
FINDINGS["AA005"]="/(usr/)?bin/(ba)?(da)?sh|Shell Execution via dhcp-script|Critical|Quick|Avoid unrestricted shell execution."
FINDINGS["AA006"]="/\\*\\*|Recursive Wildcards|Medium|Quick|Avoid '**' wildcard usage unless necessary."
FINDINGS["AA007"]="mr|Memory Read Permission|Medium|Planned|Use 'ix' instead of 'mr' if memory inspection isn't needed."
FINDINGS["AA008"]="ix|Shell Execution Trigger|Low|Quick|Restrict 'ix' use to trusted static scripts."
FINDINGS["AA009"]="/(usr/)?bin/(python|perl|ruby|node)|Mobile Code Interpreter Found|High|Quick|Remove or restrict scripting engines."
FINDINGS["AA010"]="network|Mobile Code Transfer Risk|Medium|Planned|Disable file transfer protocols unless secured."
FINDINGS["AA011"]="/media|USB Execution Risk|Medium|Planned|Block executable access from removable drives."
FINDINGS["AA012"]="/mnt|Mounted Volume Execution Risk|Medium|Planned|Restrict execution from mounted volumes."
FINDINGS["AA013"]="w /etc|Unauthorized Write to Config|Critical|Involved|Protect '/etc' from unauthorized write access."
FINDINGS["AA014"]="w /var/lib|Unauthorized Data Modification|High|Planned|Secure '/var/lib' against unintended writes."
FINDINGS["AA015"]="capability sys_module|Kernel Module Load|Critical|Involved|Restrict kernel module loading capability."
FINDINGS["AA016"]="capability sys_admin|Over-Privileged Capability|Critical|Involved|Break into granular permissions."

# ----------------------
# HTML Report Header
# ----------------------
cat <<EOF > "$OUTPUT_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>AppArmor Audit Report</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f0f2f5;
      margin: 0;
      padding: 20px;
      color: #333;
    }
    h1 {
      text-align: center;
      color: #2c3e50;
      margin-bottom: 20px;
      font-size: 2em;
      text-transform: uppercase;
      letter-spacing: 2px;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      table-layout: fixed;
      margin: 0 auto;
      background: #ffffff;
      box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid #ddd;
    }
    th, td {
      padding: 12px 15px;
      text-align: left;
      border: 1px solid #e0e0e0;
      vertical-align: top;
      height: 60px; /* Increased for better readability */
      overflow-wrap: break-word;
      word-break: break-all;
      font-size: 0.95em;
    }
    th {
      background: linear-gradient(90deg, #34495e, #2c3e50);
      color: #ffffff;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      position: sticky;
      top: 0;
    }
    .Medium {
      background: #fff3cd;
    }
    .Critical {
      background: #ff4d4d;
      color: #fff;
    }
    .Fail {
      color: #dc3545;
      font-weight: bold;
    }
    .Pass {
      color: #28a745;
      font-weight: bold;
    }
    tr {
      transition: background 0.3s ease;
    }
    tr:hover {
      background: #f8f9fa;
    }
    .MatchedLine {
      font-family: 'Courier New', Courier, monospace;
      background: #f1f3f5;
      padding: 6px;
      border-radius: 6px;
      overflow-wrap: break-word;
      word-break: break-all;
    }
    .Remediation {
      font-style: italic;
      color: #6c757d;
      overflow-wrap: break-word;
      word-break: break-all;
    }
    /* Column widths */
    th:nth-child(1), td:nth-child(1) { width: 8%; min-width: 80px; } /* Issue ID */
    th:nth-child(2), td:nth-child(2) { width: 14%; min-width: 140px; } /* Issue Name */
    th:nth-child(3), td:nth-child(3) { width: 14%; min-width: 140px; } /* File */
    th:nth-child(4), td:nth-child(4) { width: 10%; min-width: 100px; } /* Risk */
    th:nth-child(5), td:nth-child(5) { width: 10%; min-width: 100px; } /* Fix Type */
    th:nth-child(6), td:nth-child(6) { width: 8%; min-width: 80px; } /* Status */
    th:nth-child(7), td:nth-child(7) { width: 18%; min-width: 180px; } /* Matched Line */
    th:nth-child(8), td:nth-child(8) { width: 18%; min-width: 180px; } /* Remediation */

    /* Media queries */
    @media screen and (max-width: 768px) {
      table {
        font-size: 0.85em;
      }
      th, td {
        padding: 8px 10px;
        height: 50px;
      }
      h1 {
        font-size: 1.5em;
      }
      th:nth-child(1), td:nth-child(1) { width: 10%; min-width: 60px; }
      th:nth-child(2), td:nth-child(2) { width: 15%; min-width: 100px; }
      th:nth-child(3), td:nth-child(3) { width: 15%; min-width: 100px; }
      th:nth-child(4), td:nth-child(4) { width: 10%; min-width: 80px; }
      th:nth-child(5), td:nth-child(5) { width: 10%; min-width: 80px; }
      th:nth-child(6), td:nth-child(6) { width: 10%; min-width: 60px; }
      th:nth-child(7), td:nth-child(7) { width: 15%; min-width: 120px; }
      th:nth-child(8), td:nth-child(8) { width: 15%; min-width: 120px; }
    }
  </style>
</head>
<body>
<h1>AppArmor Audit Report</h1>
<table>
  <tr>
    <th>Issue ID</th>
    <th>Issue Name</th>
    <th>File</th>
    <th>Risk</th>
    <th>Fix Type</th>
    <th>Status</th>
    <th>Matched Line</th>
    <th>Remediation</th>
  </tr>
EOF

# Track matched findings
declare -A MATCHED

# Recursively find all profile files
PROFILE_FILES=$(find "$PROFILE_BASE_DIR" -type f 2>/dev/null)

for file in $PROFILE_FILES; do
  [ -f "$file" ] || continue
  [ -r "$file" ] || continue

  while IFS= read -r line || [[ -n "$line" ]]; do
    for id in "${!FINDINGS[@]}"; do
      IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
      if echo "$line" | grep -qE "$pattern" 2>/dev/null; then
        MATCHED["$id"]=1
        sanitized_line=$(echo "$line" | sed 's/</\&lt;/g; s/>/\&gt;/g')
        echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
        echo "  <td>$id</td>" >> "$OUTPUT_FILE"
        echo "  <td>$name</td>" >> "$OUTPUT_FILE"
        echo "  <td>$file</td>" >> "$OUTPUT_FILE"
        echo "  <td>$risk</td>" >> "$OUTPUT_FILE"
        echo "  <td>$fix</td>" >> "$OUTPUT_FILE"
        echo "  <td><span class=\"Fail\">Fail</span></td>" >> "$OUTPUT_FILE"
        echo "  <td class=\"MatchedLine\">$sanitized_line</td>" >> "$OUTPUT_FILE"
        echo "  <td class=\"Remediation\">$remediation</td>" >> "$OUTPUT_FILE"
        echo "</tr>" >> "$OUTPUT_FILE"
      fi
    done
  done < "$file" || continue
done

# Report passed checks
for id in "${!FINDINGS[@]}"; do
  if [[ -z "${MATCHED[$id]}" ]]; then
    IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
    echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
    echo "  <td>$id</td>" >> "$OUTPUT_FILE"
    echo "  <td>$name</td>" >> "$OUTPUT_FILE"
    echo "  <td>-</td>" >> "$OUTPUT_FILE"
    echo "  <td>$risk</td>" >> "$OUTPUT_FILE"
    echo "  <td>$fix</td>" >> "$OUTPUT_FILE"
    echo "  <td><span class=\"Pass\">Pass</span></td>" >> "$OUTPUT_FILE"
    echo "  <td class=\"MatchedLine\">-</td>" >> "$OUTPUT_FILE"
    echo "  <td class=\"Remediation\">$remediation</td>" >> "$OUTPUT_FILE"
    echo "</tr>" >> "$OUTPUT_FILE"
  fi
done

echo "</table></body></html>" >> "$OUTPUT_FILE"
echo "[+] Main AppArmor audit saved to $OUTPUT_FILE"

# ----------------------
# SR Compliance Matrix
# ----------------------
declare -A SR_COMPLIANCE=(
  ["SR 2.4"]="AA005,AA008,AA009,AA010"
  ["SR 3.2"]="AA002,AA003,AA004,AA015,AA016"
  ["SR 3.2RE1"]="AA011,AA012"
  ["SR 3.4"]="AA013,AA014"
  ["SR 5.4"]="N/A"
  ["SR 7.2"]="N/A"
  ["SR 7.7"]="AA001,AA002,AA003,AA004,AA015,AA016"
)

cat <<EOF > "$COMPLIANCE_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Compliance Matrix</title>
  <style>
    body { font-family: , sans-serif; padding: 16px; background: #f4f4f4; }
    table { border-collapse: collapse; width: 99%; background: #fff; }
    th, td { padding: 11px; border: 1px solid #ccc; }
    th { background-color: #343a40; color: white; }
    .Good { background: #d4edda; }
    .Partial { background: #fff3cd; }
    .Weak { background: #f8d7da; }
  </style>
</head>
<body>
<h1>ISA/IEC 62443 Compliance Status</h1>
<table>
  <tr>
    <th>SR ID</th>
    <th>Title</th>
    <th>Status</th>
    <th>Related Checks</th>
    <th>Comments</th>
  </tr>
EOF

function status_class {
  local sr_id="$1"
  local checks="${SR_COMPLIANCE[$sr_id]}"
  if [[ "$checks" == "N/A" ]]; then
    echo "Weak"
  else
    local found=0
    IFS=',' read -ra ids <<< "$checks"
    for id in "${ids[@]}"; do
      [[ "${MATCHED[$id]}" ]] && found=1
    done
    echo $((found)) | grep -q 1 && echo "Partial" || echo "Good"
  fi
}

declare -A SR_TITLE=(
  ["SR 2.4"]="Mobile Code"
  ["SR 3.2"]="Malicious Code Protection"
  ["SR 3.2RE1"]="Entry/Exit Protection"
  ["SR 3.4"]="Software/Information Integrity"
  ["SR 5.4"]="Application Partitioning"
  ["SR 7.2"]="Resource Management"
  ["SR 7.7"]="Least Functionality"
)

for sr in "${!SR_COMPLIANCE[@]}"; do
  title="${SR_TITLE[$sr]}"
  checks="${SR_COMPLIANCE[$sr]}"
  class=$(status_class "$sr")
  comment="Coverage based on AppArmor policy analysis."
  echo "<tr class=\"$class\">" >> "$COMPLIANCE_FILE"
  echo "<td>$sr</td><td>$title</td><td>$class</td><td>$checks</td><td>$comment</td></tr>" >> "$COMPLIANCE_FILE"
done

echo "</table></body></html>" >> "$COMPLIANCE_FILE"
echo "[+] Compliance status report saved to $COMPLIANCE_FILE"
