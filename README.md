# SCADA Sentinel

## Overview
SCADA Sentinel is a penetration testing tool designed for SCADA systems, focusing on identifying vulnerabilities in network traffic from cameras, door controllers, and alarm systems. It supports multiple protocols such as Modbus, DNP3, and OPC UA, ensuring compatibility with numerous vendors.

- **Author**: Rick Hayes
- **Version**: 1.0
- **License**: BSD

## Features
- Real-time packet sniffing and protocol analysis using Scapy.
- Automated vulnerability scanning for SCADA-related services.
- Robust error handling for malformed packets and network issues.
- Detailed PDF reporting with timestamps and vulnerability details.

## Requirements
- Python 3.6+
- Libraries:
  - `scapy` (for network scanning)
  - `pysnmp` (for SNMP probing)
  - `reportlab` (for PDF report generation)
- Install dependencies:
  ```bash
  pip install scapy pysnmp reportlab
  ```

## Usage
Run the tool from the command line with a target IP or range:
```bash
python scada_sentinel.py 192.168.1.0/24
```
Optional: Specify protocols to scan:
```bash
python scada_sentinel.py 192.168.1.0/24 --protocols modbus dnp3
```

### Output
- Logs are saved to `scada_sentinel.log`.
- A PDF report is generated with a timestamped filename (e.g., `scada_sentinel_report_20250404_123456.pdf`).

## Vendor Compatibility
- Siemens
- Schneider Electric
- Rockwell Automation
- Generic IP-based devices

## Error Handling
- Handles network timeouts, malformed packets, and protocol-specific errors.
- Logs all errors to `scada_sentinel.log` for troubleshooting.

## License
This software is licensed under the BSD License. See the LICENSE file for details.

## Disclaimer
Use this tool responsibly and only on systems you have permission to test. The author is not liable for misuse.
```

---

### Notes
- The code assumes `scapy.nmap.NmapScan()` is available, which requires the `python-nmap` library (`pip install python-nmap`). Adjust if using raw Scapy without Nmap integration.
