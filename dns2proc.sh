#!/usr/bin/env bash

# dns2proc.sh for Linux
# Logs DNS queries and correlates them with process information using auditd logs and timing correlation.
# Requires: root privileges, auditd, tcpdump
# NOTE: Audit rules will be added to the auditd config file and removed on exit
#       Check for conflicting rules, you may need to remove them manually

AUDIT_LOG_FILE="/var/log/audit/audit.log"
RED='\033[0;31m'
NC='\033[0m' # No Color

hex_to_ascii() {
    # Converts hex string (e.g. 70696E6700676F6F676C652E636F6D) to ASCII
    echo "$1" | xxd -r -p | tr '\0' ' '
}

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure auditd is running
if ! pgrep -x "auditd" > /dev/null; then
    echo "auditd is not running. Please start auditd." >&2
    exit 1
fi

# Add audit rules for connect syscall (IPv4 and IPv6)
auditctl -a always,exit -F arch=b64 -S connect 2>/dev/null || true
auditctl -a always,exit -F arch=b32 -S connect 2>/dev/null || true

# Cleanup function to remove audit rules on exit
cleanup() {
    auditctl -d always,exit -F arch=b64 -S connect 2>/dev/null || true
    auditctl -d always,exit -F arch=b32 -S connect 2>/dev/null || true
    echo "Cleaned up audit rules."
}
trap cleanup EXIT

echo -e "Listening for DNS queries and correlating with process info using auditd timing..."
echo -e "Press Ctrl+C to stop."

# More generic regex for tcpdump DNS queries
dns_regex='IP ([0-9\.]+)\.([0-9]+) > ([0-9\.]+)\.53: [0-9]+\+[^ ]* ([A-Z]+)\? ([^ ]+)'

# Main loop: process each tcpdump line
tcpdump -l -nn -i any udp port 53 2>/dev/null | while read -r line; do
    if [[ "$line" =~ $dns_regex ]]; then
        SRC_IP="${BASH_REMATCH[1]}"
        SRC_PORT="${BASH_REMATCH[2]}"
        DST_IP="${BASH_REMATCH[3]}"
        DNS_TYPE="${BASH_REMATCH[4]}"
        DNS_QUERY="${BASH_REMATCH[5]}"

        # Get the last 3 SOCKADDR events with lport=53
        EVENT_IDS=( $(grep 'type=SOCKADDR' "$AUDIT_LOG_FILE" | grep 'lport=53' | tail -3 | grep -oP 'msg=audit\(\K[0-9.]+:[0-9]+') )
        if [[ ${#EVENT_IDS[@]} -eq 0 ]]; then
            echo -e "[$(date)] No audit log found for DNS query: ${RED}$DNS_TYPE $DNS_QUERY${NC} from $SRC_IP:$SRC_PORT"
            continue
        fi
        echo -e "[$(date)] Possible processes for DNS query: ${RED}$DNS_TYPE $DNS_QUERY${NC} from $SRC_IP:$SRC_PORT"
        declare -A seen_lines
        for EVENT_ID in "${EVENT_IDS[@]}"; do
            SYSCALL_LINE=$(grep 'type=SYSCALL' "$AUDIT_LOG_FILE" | grep "$EVENT_ID" | tail -1)
            PROCTITLE_LINE=$(grep 'type=PROCTITLE' "$AUDIT_LOG_FILE" | grep "$EVENT_ID" | tail -1)
            if [[ -n "$SYSCALL_LINE" ]]; then
                COMM=$(echo "$SYSCALL_LINE" | grep -oP 'comm="\K[^ "]+')
                EXE=$(echo "$SYSCALL_LINE" | grep -oP 'exe="\K[^ "]+')
                AUDIT_PID=$(echo "$SYSCALL_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /^pid=/) {split($i,a,"="); print a[2]}}')
                AUDIT_PPID=$(echo "$SYSCALL_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /^ppid=/) {split($i,a,"="); print a[2]}}')
                AUDIT_UID=$(echo "$SYSCALL_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /^uid=/) {split($i,a,"="); print a[2]}}')
                AUDIT_EUID=$(echo "$SYSCALL_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /^euid=/) {split($i,a,"="); print a[2]}}')
                AUDIT_AUID=$(echo "$SYSCALL_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /^auid=/) {split($i,a,"="); print a[2]}}')
                USERNAME_UID=$(getent passwd "$AUDIT_UID" | cut -d: -f1)
                USERNAME_EUID=$(getent passwd "$AUDIT_EUID" | cut -d: -f1)
                USERNAME_AUID=$(getent passwd "$AUDIT_AUID" | cut -d: -f1)
                if [[ -n "$PROCTITLE_LINE" ]]; then
                    PROCTITLE_HEX=$(echo "$PROCTITLE_LINE" | grep -oP 'proctitle=\K[0-9a-fA-F]+')
                    CMDLINE=$(hex_to_ascii "$PROCTITLE_HEX")
                else
                    CMDLINE="(not found)"
                fi
                # Lookup parent process info from /proc
                PARENT_NAME="(not found)"
                PARENT_EXE="(not found)"
                if [[ -n "$AUDIT_PPID" && -d "/proc/$AUDIT_PPID" ]]; then
                    if [[ -r "/proc/$AUDIT_PPID/comm" ]]; then
                        PARENT_NAME=$(cat "/proc/$AUDIT_PPID/comm" 2>/dev/null)
                    fi
                    if [[ -L "/proc/$AUDIT_PPID/exe" ]]; then
                        PARENT_EXE=$(readlink -f "/proc/$AUDIT_PPID/exe" 2>/dev/null)
                    fi
                fi
                PROC_LINE="    comm=$COMM exe=${RED}$EXE${NC} cmdline=\"$CMDLINE\" PID=$AUDIT_PID PPID=$AUDIT_PPID UID=$AUDIT_UID($USERNAME_UID) EUID=$AUDIT_EUID($USERNAME_EUID) AUID=${RED}$AUDIT_AUID($USERNAME_AUID)${NC} parent_name=\"$PARENT_NAME\" parent_exe=\"${RED}$PARENT_EXE${NC}\""
                if [[ -z "${seen_lines[$PROC_LINE]+x}" ]]; then
                    echo -e "$PROC_LINE"
                    seen_lines[$PROC_LINE]=1
                fi
            else
                echo "    No SYSCALL found for event $EVENT_ID"
            fi
        done
        unset seen_lines
    fi
    true
done
