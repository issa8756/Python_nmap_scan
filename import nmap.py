import nmap
import pprint


nm = nmap.PortScanner()
ip_addresses = []
scan_data = {}

def add_ip_addresses():
    """Add IP addresses to the list manually."""
    global ip_addresses, scan_data
    ip_input = input("🔧 Enter one or more IP addresses (comma-separated): ").strip()
    ip_addresses = [ip.strip() for ip in ip_input.split(',')]
    scan_data = {}  # Reset stored scan data if new IPs are entered
    print(f"✅ IP addresses added: {ip_addresses}")

def add_ip_addresses_from_file():
    """Load IP addresses from a file."""
    global ip_addresses, scan_data
    filename = input("📄 Enter the filename containing IP addresses (e.g., ips.txt): ").strip()
    try:
        with open(filename, 'r') as file:
            ip_addresses = [line.strip() for line in file if line.strip()]
            scan_data = {}  # Reset stored scan data if new IPs are loaded
        print(f"✅ IP addresses loaded from file: {ip_addresses}")
    except FileNotFoundError:
        print(f"❌ File '{filename}' not found. Please ensure the file exists and try again.")
    except Exception as e:
        print(f"❌ An error occurred while reading the file: {e}")

def perform_scan():
    """Perform the scan on the listed IP addresses."""
    global scan_data
    for ip in ip_addresses:
        print(f"🔍 Scanning {ip} ...")
        nm.scan(ip, arguments='-sV -T4 -Pn')
        scan_data[ip] = nm[ip]
        print(f"✅ Scan completed for {ip}.")

def show_open_ports(ip):
    """Display open ports for the given IP."""
    print(f"\n🔓 Open Ports for {ip}:")
    for proto in scan_data[ip].all_protocols():
        for port in scan_data[ip][proto].keys():
            if scan_data[ip][proto][port]['state'] == 'open':
                print(f"Port {port} is open.")

def show_services(ip):
    """Display services running on open ports for the given IP."""
    print(f"\n🛠️ Services on Open Ports for {ip}:")
    for proto in scan_data[ip].all_protocols():
        for port in scan_data[ip][proto].keys():
            state = scan_data[ip][proto][port]['state']
            service_info = scan_data[ip][proto][port].get('name', 'Unknown Service')
            version_info = scan_data[ip][proto][port].get('version', 'Unknown Version')
            print(f"Port {port}: {service_info} (Version: {version_info}) - {state}")

def show_os_detection(ip):
    """Display the operating system detected for the given IP."""
    os_info = scan_data[ip].get('osmatch', 'No OS found')
    print(f"🖥️ Operating System for {ip}: {os_info}")

def save_results_to_file(filename):
    """Save the scan results to a specified text file."""
    with open(filename, 'w') as file:
        for ip, result in scan_data.items():
            file.write(f"Results for {ip}:\n")
            pprint.pprint(result, stream=file)
            file.write("\n")
    print(f"✅ Results saved to {filename}")

def clear_previous_results():
    """Clear the previously stored scan results."""
    global scan_data
    scan_data = {}
    print("🗑️ Previous scan results cleared.")

def show_all_results():
    """Display all scan results for all IPs."""
    for ip in ip_addresses:
        print(f"\n🔍 Results for {ip}:")
        pprint.pprint(scan_data[ip])

def show_menu():
    """Display the main menu options."""
    print("\n🌐 Main Menu:")
    print("1. Enter IP addresses manually")
    print("2. Load IP addresses from a file (each IP should be on a separate line)")
    print("3. Perform scan for all IPs")
    print("4. Show open ports")
    print("5. Show services on open ports")
    print("6. Show OS detection")
    print("7. Save results to a file")
    print("8. Clear previous results")
    print("9. Show all scan results")
    print("10. Exit")

def main():
    """Main function to run the Nmap scanner program."""
    while True:
        show_menu()
        choice = input("🔍 Select an option (1-10): ").strip()
        
        if choice == '1':
            add_ip_addresses()
        elif choice == '2':
            add_ip_addresses_from_file()
        elif choice == '3':
            if not ip_addresses:
                print("❌ Please enter or load IP addresses first using option 1 or 2.")
            else:
                perform_scan()
        elif choice in ['4', '5', '6']:
            if not scan_data:
                print("❌ Please perform a scan first using option 3.")
            else:
                for ip in ip_addresses:
                    print(f"\nDisplaying results for {ip} ...")
                    if choice == '4':
                        show_open_ports(ip)
                    elif choice == '5':
                        show_services(ip)
                    elif choice == '6':
                        show_os_detection(ip)
        elif choice == '7':
            filename = input("📁 Enter filename to save results (e.g., results.txt): ")
            save_results_to_file(filename)
        elif choice == '8':
            clear_previous_results()
        elif choice == '9':
            if not scan_data:
                print("❌ No scan data available. Please perform a scan first.")
            else:
                show_all_results()
        elif choice == '10':
            print("🚪 Exiting the program.")
            break
        else:
            print("❌ Invalid option, please try again.")


if __name__ == "__main__":
    main()
