#!/bin/bash

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
    body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 20px; }
    table { border-collapse: collapse; width: 100%; table-layout: fixed; }
    th, td { padding: 10px; border: 1px solid #ccc; text-align: left; vertical-align: top; word-wrap: break-word; white-space: pre-wrap; }
    th { background: #343a40; color: #fff; }
    .Critical { background: #ff4d4d; }
    .High { background: #ffa94d; }
    .Medium { background: #fff3cd; }
    .Low { background: #d4edda; }
    .Pass { color: green; font-weight: bold; }
    .Fail { color: red; font-weight: bold; }
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
PROFILE_FILES=$(find "$PROFILE_BASE_DIR" -type f)

for file in $PROFILE_FILES; do
  [ -f "$file" ] || continue

  while IFS= read -r line || [[ -n "$line" ]]; do
    for id in "${!FINDINGS[@]}"; do
      IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
      if echo "$line" | grep -qE "$pattern" 2>/dev/null; then
        MATCHED["$id"]=1
        sanitized_line=$(echo "$line" | sed 's/</\&lt;/g')
        echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
        echo "<td>$id</td><td>$name</td><td>${file}</td><td>$risk</td><td>$fix</td>" >> "$OUTPUT_FILE"
        echo "<td class=\"Fail\">Fail</td><td>$sanitized_line</td><td>$remediation</td></tr>" >> "$OUTPUT_FILE"
      fi
    done
  done < "$file"
done

# Report passed checks
for id in "${!FINDINGS[@]}"; do
  if [[ -z "${MATCHED[$id]}" ]]; then
    IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
    echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
    echo "<td>$id</td><td>$name</td><td>-</td><td>$risk</td><td>$fix</td>" >> "$OUTPUT_FILE"
    echo "<td class=\"Pass\">Pass</td><td>-</td><td>$remediation</td></tr>" >> "$OUTPUT_FILE"
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
    body { font-family: Arial, sans-serif; padding: 20px; background: #f4f4f4; }
    table { border-collapse: collapse; width: 100%; background: #fff; }
    th, td { padding: 10px; border: 1px solid #ccc; }
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
