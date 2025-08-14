import nmap
import time
import socket

security_advice = {
    21:  "FTP detected — Configure the firewall appropriately if in use. For secure transfers, use SFTP (port 22) or FTPS (ports 989/990).",
    22:  "SSH detected — Ensure strong authentication and restrict access to trusted IPs. Enable SSH tunneling where appropriate.",
    23:  "Telnet detected — Telnet is insecure and deprecated. Replace with SSH and disable this port.",
    25:  "SMTP detected — Restrict use to secure mail relaying between trusted servers. Implement proper server hardening.",
    53:  "DNS detected — Implement protections against DDoS and spoofing. Consider randomizing query source ports for security.",
    80:  "HTTP detected — Redirect traffic to HTTPS (port 443) and consider implementing HTTP Strict Transport Security (HSTS).",
    111: "RPC detected — Restrict access to trusted networks only. Keep software updated and monitor traffic closely.",
    139: "NetBIOS-SSN detected — Use SMB over port 445 instead. Running SMB over VPN can improve security but may impact performance.",
    445: "Microsoft-DS detected — Use SMB 3.0 with encryption. Consider running over VPN for sensitive environments.",
    512: "Exec service detected — Restrict to trusted sources and use strong authentication. Disable if not required.",
    513: "Login service detected — Use strong credentials and multi-factor authentication. Disable if unused.",
    514: "Syslog detected — Make log files append-only and sanitize sensitive data. Restrict source IPs.",
    1099:"RMI Registry detected — Restrict access to trusted sources. Use authentication and keep Java updated.",
    1524:"Ingresslock detected — Monitor for unauthorized access. Disable if not required.",
    2049:"NFS detected — Restrict access, require authentication, and keep software updated.",
    2121:"CCProxy FTP detected — Configure firewall if in use. For secure transfers, use SFTP (port 22) or FTPS (ports 989/990).",
    3306:"MySQL detected — Require strong credentials, enable encryption, and validate all user inputs.",
    5432:"PostgreSQL detected — Restrict access, enforce strong authentication, and keep software updated.",
    5900:"VNC detected — Limit access to trusted sources, enable encryption, and keep software updated.",
    6000:"X11 detected — Restrict access to SSH tunnels only. Keep software updated.",
    6667:"IRC detected — Restrict access, enable authentication/encryption, and consider modern alternatives.",
    8009:"AJP13 detected — Restrict access via firewall, enable authentication, and keep software updated.",
    8180:"AltHTTP detected — Disable default web applications, require strong credentials, and keep server updated."
}

def validate_target(target):
    """Check if the input is a valid IP or domain."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False

def scan_ports(target):
    """Scan target using Nmap and display open ports with service info and security advice."""
    scanner = nmap.PortScanner()

    print(f"\nStarting scan on: {target}")
    print("=" * 50)

    start_time = time.time()

    output = []
    try:
        # Scan top 1000 ports with service/version detection
        scanner.scan(target, arguments='-sV')

        if not scanner.all_hosts():
            print("No response from target. It might be down or blocking scans.")
            return

        for host in scanner.all_hosts():
            output.append(f"Host: {host} ({scanner[host].hostname()})")
            output.append(f"State: {scanner[host].state()}")

            open_ports = []
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port]['version']

                    if state == 'open':
                        open_ports.append((port, proto, service, version))

            if open_ports:
                output.append("\nOpen Ports Found:")
                for port, proto, service, version in open_ports:
                    output.append(f"  [+] {port}/{proto} - {service} {version}")

                
                output.append("\nSecurity Advice:")
                advice_given = False
                for port, _, _, _ in open_ports:
                    if port in security_advice:
                        output.append(f" - Port {port}: {security_advice[port]}")
                        advice_given = True
                if not advice_given:
                    output.append(" - No specific advice for detected open ports.")

            else:
                output.append("\nNo open ports found.")

    except Exception as e:
        print(f"Error occurred: {e}")
        return

    end_time = time.time()
    duration = end_time - start_time

    output.append("\n" + "=" * 50)
    output.append(f"Scan completed in {duration:.2f} seconds.")

    # Print all output 
    full_output = "\n".join(output)
    print(full_output)

if __name__ == "__main__":
    target_ip = input("Enter target IP or domain to scan: ").strip()
    if validate_target(target_ip):
        scan_ports(target_ip)
    else:
        print("Invalid target. Please enter a valid IP address or domain.")
