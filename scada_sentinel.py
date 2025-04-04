#!/usr/bin/env python3
"""
SCADA Sentinel - A penetration testing tool for SCADA systems
Author: Rick Hayes
Version: 1.0
License: BSD
"""

import scapy.all as scapy
import pysnmp.hlapi as snmp
import reportlab.lib.pagesizes as pagesizes
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import argparse
import logging
import threading
import time
from datetime import datetime
import socket
import sys

# Configure logging
logging.basicConfig(filename='scada_sentinel.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class ScadaSentinel:
    def __init__(self, target_ip, protocols=None):
        self.target_ip = target_ip
        self.protocols = protocols if protocols else ['modbus', 'dnp3', 'opcua']
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.report_file = f"scada_sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    def scan_network(self):
        """Scan the network for open ports and services."""
        try:
            logging.info(f"Starting network scan on {self.target_ip}")
            nm = scapy.nmap.NmapScan()
            nm.scan(hosts=self.target_ip, arguments="-sV --open")
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        logging.info(f"Found service {service} on {host}:{port}")
                        self.check_vulnerability(host, port, service)
        except Exception as e:
            logging.error(f"Network scan failed: {e}")

    def check_vulnerability(self, host, port, service):
        """Check for known vulnerabilities based on service."""
        with self.lock:
            if 'modbus' in service.lower() and '502' in str(port):
                self.vulnerabilities.append(f"{host}:{port} - Modbus open, potential unauthenticated access")
            elif 'dnp3' in service.lower():
                self.vulnerabilities.append(f"{host}:{port} - DNP3 detected, check for weak encryption")
            elif 'opc' in service.lower():
                self.vulnerabilities.append(f"{host}:{port} - OPC UA exposed, verify authentication")
            else:
                self.vulnerabilities.append(f"{host}:{port} - Unknown service: {service}")

    def snmp_probe(self):
        """Probe SNMP for additional information."""
        try:
            logging.info(f"Probing SNMP on {self.target_ip}")
            for (errorIndication, errorStatus, errorIndex, varBinds) in snmp.getCmd(
                snmp.SnmpEngine(),
                snmp.CommunityData('public', mpModel=0),
                snmp.UdpTransportTarget((self.target_ip, 161)),
                snmp.ContextData(),
                snmp.ObjectType(snmp.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ):
                if errorIndication or errorStatus:
                    logging.warning(f"SNMP probe failed: {errorIndication or errorStatus}")
                else:
                    for varBind in varBinds:
                        self.vulnerabilities.append(f"SNMP Info: {varBind.prettyPrint()}")
        except Exception as e:
            logging.error(f"SNMP probe failed: {e}")

    def generate_report(self):
        """Generate a PDF report of findings."""
        try:
            doc = SimpleDocTemplate(self.report_file, pagesize=pagesizes.letter)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph("SCADA Sentinel Report", styles['Title']))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"Target: {self.target_ip}", styles['Normal']))
            story.append(Paragraph(f"Date: {datetime.now()}", styles['Normal']))
            story.append(Spacer(1, 12))

            story.append(Paragraph("Vulnerabilities Found:", styles['Heading2']))
            for vuln in self.vulnerabilities:
                story.append(Paragraph(vuln, styles['Normal']))
                story.append(Spacer(1, 6))

            doc.build(story)
            logging.info(f"Report generated: {self.report_file}")
            print(f"Report saved as {self.report_file}")
        except Exception as e:
            logging.error(f"Report generation failed: {e}")

    def run(self):
        """Run the full scan and reporting process."""
        threads = []
        threads.append(threading.Thread(target=self.scan_network))
        threads.append(threading.Thread(target=self.snmp_probe))

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description="SCADA Sentinel - SCADA Penetration Testing Tool")
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.0/24)")
    parser.add_argument("--protocols", nargs='+', help="Protocols to scan (e.g., modbus dnp3 opcua)")
    args = parser.parse_args()

    sentinel = ScadaSentinel(args.target, args.protocols)
    sentinel.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
