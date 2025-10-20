# vuln_scanner.py
# This script automates Nmap vulnerability scanning using Python and NSE.

import subprocess
import argparse
import re
import os
import xml.etree.ElementTree as ET

def validate_target(target):
    """Validates the target format (IP address, CIDR, or hostname)."""
    ip_cidr_pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?)$")
    hostname_pattern = re.compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
    if ip_cidr_pattern.match(target) or hostname_pattern.match(target):
        return True
    return False

def run_nmap_vuln_scan(target, nmap_script_args, output_file_base, extra_nmap_options):
    """Runs an Nmap vulnerability scan with specified NSE scripts.

    Args:
        target (str): The target IP address, range (CIDR), or hostname.
        nmap_script_args (str): Nmap script arguments (e.g., "vuln").
        output_file_base (str): The base name for output files.
        extra_nmap_options (list): Additional Nmap options.
    """
    if not validate_target(target):
        print(f"Error: Invalid target format 	'{target}'. Please use an IP, CIDR, or valid hostname.")
        return

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

    command = ["sudo", "nmap", "-sV"] # -sV is generally useful for NSE scripts
    if nmap_script_args:
        command.extend(["--script", nmap_script_args])
    
    command.extend(extra_nmap_options)
    command.extend(["-oX", xml_output, "-oG", grepable_output, "-oN", normal_output, target])

    print(f"Running Nmap vulnerability scan: {' '.join(command)}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False)

        print("\n--- Nmap Normal Output ---")
        print(process.stdout)
        if process.stderr:
            print("\n--- Nmap Error Output ---")
            print(process.stderr)

        if process.returncode == 0:
            print(f"\nNmap vulnerability scan completed successfully.")
        else:
            if "Note: Host seems down." in process.stdout or "Note: Host seems down." in process.stderr:
                 print(f"\nNmap scan completed. Note: Target host {target} seems down.")
            else:
                print(f"\nNmap vulnerability scan completed with return code: {process.returncode}. Check output above.")

        print(f"Scan results saved:")
        print(f"  XML: {xml_output}")
        print(f"  Grepable: {grepable_output}")
        print(f"  Normal: {normal_output}")

        if os.path.exists(xml_output):
            print("\n--- Parsed Vulnerabilities (from XML) ---")
            parse_nmap_vuln_xml(xml_output)

    except subprocess.CalledProcessError as e:
        print(f"Error during Nmap vulnerability scan: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def parse_nmap_vuln_xml(xml_file):
    """Parses Nmap XML output to extract vulnerability information from NSE scripts."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        vulnerabilities_found = False
        for host in root.findall("host"):
            ip_address = host.find("address").get("addr")
            host_printed = False
            ports_element = host.find("ports")
            if ports_element is not None:
                for port_element in ports_element.findall("port"):
                    portid = port_element.get("portid")
                    protocol = port_element.get("protocol")
                    service_name_elem = port_element.find("service")
                    service_name = service_name_elem.get("name", "N/A") if service_name_elem is not None else "N/A"
                    
                    port_scripts = port_element.findall("script")
                    for script in port_scripts:
                        script_id = script.get("id")
                        script_output = script.get("output")
                        # Heuristic: if 'VULNERABLE' or 'State: VULNERABLE' is in output, consider it a finding
                        # More sophisticated parsing would look for specific script table structures (e.g., CVEs)
                        if script_output and ("VULNERABLE" in script_output.upper() or "CVE-" in script_output.upper()):
                            if not host_printed:
                                print(f"\nHost: {ip_address}")
                                host_printed = True
                            vulnerabilities_found = True
                            print(f"  Port: {portid}/{protocol} ({service_name})")
                            print(f"    Script: {script_id}")
                            print(f"    Output: \n{script_output.strip()}\n")
            
            host_scripts = host.find("hostscript")
            if host_scripts is not None:
                 for script in host_scripts.findall("script"):
                    script_id = script.get("id")
                    script_output = script.get("output")
                    if script_output and ("VULNERABLE" in script_output.upper() or "CVE-" in script_output.upper()):
                        if not host_printed:
                            print(f"\nHost: {ip_address}")
                            host_printed = True
                        vulnerabilities_found = True
                        print(f"  Host-level Script: {script_id}")
                        print(f"    Output: \n{script_output.strip()}\n")

        if not vulnerabilities_found:
            print("No specific vulnerabilities flagged by the script parser in the output.")
            print("Review the full Nmap output (.nmap, .xml) for detailed script results.")

    except FileNotFoundError:
        print(f"Error: XML file '{xml_file}' not found for parsing.")
    except ET.ParseError:
        print(f"Error: Could not parse XML file '{xml_file}'. It might be corrupted or not valid XML.")
    except Exception as e:
        print(f"An error occurred during XML vulnerability parsing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Nmap Vulnerability Scanner using NSE. Requires sudo.")
    parser.add_argument("target", help="Target IP address, CIDR range, or hostname.")
    parser.add_argument("--scripts", help="Nmap NSE script(s) or categories to run (e.g., vuln, default, or http-title). Default: 'vuln' category.", default="vuln")
    parser.add_argument("-p", "--ports", help="Ports to scan for vulnerabilities (e.g., 80,443 or 1-1024). Default: Nmap default (scans ports found open by -sV).", default=None)
    parser.add_argument("-T", "--timing", choices=["0", "1", "2", "3", "4", "5"], help="Set Nmap timing template (0-5). T4 is default.", default="4")
    parser.add_argument("-o", "--output", help="Base name for output files (e.g., vuln_scan_results). Extensions .xml, .gnmap, .nmap will be added.", default="vuln_scan_output")
    parser.add_argument("--extra_options", help="Provide additional Nmap options as a single string, e.g., '--script-args http.useragent=MyCustomAgent -v'", default="")

    args = parser.parse_args()

    nmap_extra_opts = []
    if args.ports:
        nmap_extra_opts.extend(["-p", args.ports])
    if args.timing:
        nmap_extra_opts.extend(["-T" + args.timing])
    if args.extra_options:
        nmap_extra_opts.extend(args.extra_options.split())

    run_nmap_vuln_scan(args.target, args.scripts, args.output, nmap_extra_opts)

