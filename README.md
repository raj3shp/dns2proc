# dns2proc.sh

A rudimentary script for Linux that correlates DNS queries with the processes that made them.

While eBPF-based solutions exist for modern kernels, older Linux systems lack effective tools for DNS-to-process correlation. Traditional network monitoring tools like `tcpdump` capture DNS traffic but cannot identify which process initiated each query.

`dns2proc.sh` leverages Linux auditd logs and timing correlation to bridge this gap. By monitoring DNS queries via `tcpdump` and correlating them with auditd syscall events, the script provides real-time visibility into which processes are making specific DNS requests.

Useful for incident response and forensic investigations. 

## Requirements
- Linux
- tcpdump
- auditd

## Limitations

**Accuracy Disclaimer**: This script provides correlation based on timing and auditd events, but is not 100% accurate. Several factors can affect correlation accuracy:

**Manual verification is always required** for critical investigations. This script should be used as part of a comprehensive forensic analysis workflow, not as the sole source of truth. Always cross-reference results with additional logs, system state analysis, and other forensic evidence.
