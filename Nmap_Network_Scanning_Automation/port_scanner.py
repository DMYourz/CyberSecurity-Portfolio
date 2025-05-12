# port_scanner.py
# This script automates Nmap port scanning using Python.

import subprocess
import argparse
import re
import os

def validate_target(target):
    """Validates the target format (IP address, CIDR, or hostname)."""
    # Basic regex for IP address, CIDR, and hostname
    # This is a simplified validation and might not cover all edge cases for hostnames.
    ip_cidr_pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?)$")
    # Hostname pattern: allows letters, numbers, hyphens, and dots.
    # Does not allow hyphen at start/end of a segment or consecutive hyphens.
    hostname_pattern = re.compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
    if ip_cidr_pattern.match(target) or hostname_pattern.match(target):
        return True
    return False

def run_nmap_scan(target, options, output_file_base):
    """Runs an Nmap scan with the specified target and options, saving results.

    Args:
        target (str): The target IP address, range (CIDR), or hostname.
        options (list): A list of Nmap options (e.g., ["-sS", "-T4"]).
        output_file_base (str): The base name for output files (without extension).
    """
    if not validate_target(target):
        print(f"Error: Invalid target format 	'{target}	'. Please use an IP, CIDR, or valid hostname.")
        return

    # Ensure Nmap is installed (basic check)
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, check=True, text=True)
    except FileNotFoundError:
        print("Error: Nmap is not installed or not found in PATH. Please install Nmap.")
        return
    except subprocess.CalledProcessError as e:
        print(f"Error checking Nmap version: {e}")
        return

    xml_output = f"{output_file_base}.xml"
    grepable_output = f"{output_file_base}.gnmap"
    normal_output = f"{output_file_base}.nmap"

    command = ["sudo", "nmap"] + options + ["-oX", xml_output, "-oG", grepable_output, "-oN", normal_output, target]

    print(f"Running Nmap scan: {	' 	'.join(command)}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False) # check=False to handle nmap non-zero exits gracefully
        
        print("\n--- Nmap Normal Output ---")
        print(process.stdout)
        if process.stderr:
            print("\n--- Nmap Error Output ---")
            print(process.stderr)
        
        if process.returncode == 0:
            print(f"\nNmap scan completed successfully.")
        else:
            # Nmap can return non-zero if no hosts are up, even if the scan itself ran.
            if "Note: Host seems down." in process.stdout or "Note: Host seems down." in process.stderr:
                 print(f"\nNmap scan completed. Note: Target host {target} seems down.")
            else:
                print(f"\nNmap scan completed with return code: {process.returncode}. Check output above.")

        print(f"Scan results saved:")
        print(f"  XML: {xml_output}")
        print(f"  Grepable: {grepable_output}")
        print(f"  Normal: {normal_output}")

        # Basic parsing example (can be expanded)
        if os.path.exists(xml_output):
            print("\n--- Basic Parsed Open Ports (from XML) ---")
            parse_nmap_xml_basic(xml_output)

    except subprocess.CalledProcessError as e:
        print(f"Error during Nmap scan: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def parse_nmap_xml_basic(xml_file):
    """A very basic parser for Nmap XML to show open ports.
       For more complex parsing, consider libraries like libnmap or xml.etree.ElementTree for detailed extraction.
    """
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            ip_address = host.find("address").get("addr")
            print(f"Host: {ip_address}")
            ports_element = host.find("ports")
            if ports_element is not None:
                for port_element in ports_element.findall("port"):
                    if port_element.find("state").get("state") == "open":
                        protocol = port_element.get("protocol")
                        portid = port_element.get("portid")
                        service_name = port_element.find("service").get("name", "N/A")
                        print(f"  Open Port: {portid}/{protocol} - Service: {service_name}")
            else:
                print("  No open ports found or ports element missing.")
    except FileNotFoundError:
        print(f"Error: XML file 	'{xml_file}	' not found for parsing.")
    except ET.ParseError:
        print(f"Error: Could not parse XML file 	'{xml_file}	'. It might be corrupted or not valid XML.")
    except Exception as e:
        print(f"An error occurred during XML parsing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Nmap Port Scanner. Requires sudo for some scan types (e.g., -sS).")
    parser.add_argument("target", help="Target IP address, CIDR range, or hostname.")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443 or 1-1000 or U:53,T:21-25). Default: Nmap default (top 1000 TCP ports).", default=None)
    parser.add_argument("--top-ports", type=int, help="Scan the top N most common ports as rated by Nmap.")
    parser.add_argument("-sS", "--syn_scan", action="store_true", help="Perform a TCP SYN (stealth) scan. Requires sudo.")
    parser.add_argument("-sT", "--connect_scan", action="store_true", help="Perform a TCP connect scan.")
    parser.add_argument("-sU", "--udp_scan", action="store_true", help="Perform a UDP scan.")
    parser.add_argument("-sV", "--service_version", action="store_true", help="Probe open ports to determine service/version info.")
    parser.add_argument("-O", "--os_detection", action="store_true", help="Enable OS detection. Requires sudo.")
    parser.add_argument("-T", "--timing", choices=["0", "1", "2", "3", "4", "5"], help="Set Nmap timing template (0-5). T4 is default for Nmap, T0 is slowest, T5 is fastest.", default="4")
    parser.add_argument("-o", "--output", help="Base name for output files (e.g., scan_results). Extensions .xml, .gnmap, .nmap will be added.", default="port_scan_output")
    parser.add_argument("--extra_options", help="Provide additional Nmap options as a single string, e.g., 	'-A -v	'", default="")

    args = parser.parse_args()

    nmap_options = []

    if args.syn_scan:
        nmap_options.append("-sS")
    elif args.connect_scan:
        nmap_options.append("-sT")
    elif args.udp_scan:
        nmap_options.append("-sU")
    # Default to SYN scan if sudo is available and no other scan type is chosen, else TCP connect scan
    # This logic might be too complex for a simple script; user should specify scan type.
    # For now, if no scan type is specified, Nmap's default (usually -sS if privileged, -sT otherwise) will be used.

    if args.ports:
        nmap_options.extend(["-p", args.ports])
    elif args.top_ports:
        nmap_options.extend(["--top-ports", str(args.top_ports)])
    
    if args.service_version:
        nmap_options.append("-sV")
    if args.os_detection:
        nmap_options.append("-O")
    
    if args.timing:
        nmap_options.extend(["-T" + args.timing])

    if args.extra_options:
        nmap_options.extend(args.extra_options.split())
    
    # Default to a common, relatively safe set of options if none are specified for scan type
    if not any(sc_opt in nmap_options for sc_opt in ["-sS", "-sT", "-sU"]):
        print("No specific scan type selected. Defaulting to Nmap's standard behavior (often TCP SYN scan if privileged).")

    run_nmap_scan(args.target, nmap_options, args.output)

