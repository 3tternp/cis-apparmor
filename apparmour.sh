#!/bin/bash

INPUT_DIR="./apparmor_profiles"
OUTPUT_FILE="apparmor_audit_report.html"

# ----------------------
# Define findings (array of associative arrays)
# ----------------------
declare -A FINDINGS

# Format: FINDINGS[<ID>] = "pattern|Issue Name|Risk|Fixing Type|Remediation"
FINDINGS["AA001"]="capability dac_override|Bypass File Permissions|Critical|Involved|Remove 'capability dac_override' unless essential. Use more specific capabilities instead."
FINDINGS["AA002"]="capability ptrace|Memory Inspection via Ptrace|High|Planned|Avoid ptrace access. Remove unless debugging tools explicitly require it."
FINDINGS["AA003"]="capability net_admin|Network Configuration Control|High|Involved|Only allow if AppArmor profile manages virtual bridges or network interfaces."
FINDINGS["AA004"]="capability net_raw|Raw Network Access|High|Involved|Use only if DHCP ping checks are mandatory. Otherwise remove."
FINDINGS["AA005"]="/{,usr/}bin/{ba,da,}sh|Shell Execution via dhcp-script|Critical|Quick|Whitelist specific scripts instead of broad shell access."
FINDINGS["AA006"]="/\*\*|Recursive Wildcards|Medium|Quick|Avoid recursive '**' unless the folder content is strictly controlled."
FINDINGS["AA007"]="mr|Memory Read Permission|Medium|Planned|Replace with 'ix' if no runtime memory inspection is needed."
FINDINGS["AA008"]="ix|Shell Execution|Low|Quick|Use only for known static scripts used in AppArmor triggers."

# HTML Header
cat <<EOF > "$OUTPUT_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>AppArmor Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 20px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
    th { background-color: #343a40; color: white; }
    .Critical { background-color: #ff4d4d; }
    .High { background-color: #ffa94d; }
    .Medium { background-color: #fff3cd; }
    .Low { background-color: #d4edda; }
    .Pass { color: green; font-weight: bold; }
    .Fail { color: red; font-weight: bold; }
    h1 { color: #333; }
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
    <th>Fixing Type</th>
    <th>Status</th>
    <th>Matched Line</th>
    <th>Remediation</th>
  </tr>
EOF

# Process each profile file
for file in "$INPUT_DIR"/*; do
  [ -f "$file" ] || continue

  while IFS= read -r line || [[ -n "$line" ]]; do
    for id in "${!FINDINGS[@]}"; do
      IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
      if echo "$line" | grep -qE "$pattern"; then
        echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
        echo "<td>$id</td>" >> "$OUTPUT_FILE"
        echo "<td>$name</td>" >> "$OUTPUT_FILE"
        echo "<td>$(basename "$file")</td>" >> "$OUTPUT_FILE"
        echo "<td>$risk</td>" >> "$OUTPUT_FILE"
        echo "<td>$fix</td>" >> "$OUTPUT_FILE"
        echo "<td class=\"Fail\">Fail</td>" >> "$OUTPUT_FILE"
        echo "<td><pre>${line//</&lt;}</pre></td>" >> "$OUTPUT_FILE"
        echo "<td>$remediation</td>" >> "$OUTPUT_FILE"
        echo "</tr>" >> "$OUTPUT_FILE"
      fi
    done
  done < "$file"
done

# Check passed status (no matching lines = Pass)
for id in "${!FINDINGS[@]}"; do
  IFS="|" read -r pattern name risk fix remediation <<< "${FINDINGS[$id]}"
  match_found=$(grep -Er "$pattern" "$INPUT_DIR" | wc -l)
  if [[ "$match_found" -eq 0 ]]; then
    echo "<tr class=\"$risk\">" >> "$OUTPUT_FILE"
    echo "<td>$id</td>" >> "$OUTPUT_FILE"
    echo "<td>$name</td>" >> "$OUTPUT_FILE"
    echo "<td>-</td>" >> "$OUTPUT_FILE"
    echo "<td>$risk</td>" >> "$OUTPUT_FILE"
    echo "<td>$fix</td>" >> "$OUTPUT_FILE"
    echo "<td class=\"Pass\">Pass</td>" >> "$OUTPUT_FILE"
    echo "<td>-</td>" >> "$OUTPUT_FILE"
    echo "<td>$remediation</td>" >> "$OUTPUT_FILE"
    echo "</tr>" >> "$OUTPUT_FILE"
  fi
done

# Close HTML
cat <<EOF >> "$OUTPUT_FILE"
</table>
</body>
</html>
EOF

echo "[+] Report saved to $OUTPUT_FILE"
