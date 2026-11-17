"""
Lightweight Web Server for AutoForens-NLP Digital Forensic Dashboard
Uses Python standard library http.server (no external dependencies required).
"""

import http.server
import socketserver
import os
import webbrowser

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start_server(open_browser=True):
    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}/dashboard.html"
        print("=" * 70)
        print("  AUTOFORENS-NLP: INTERACTIVE DIGITAL FORENSIC DASHBOARD")
        print("=" * 70)
        print(f"[+] Serving forensic investigation suite at:")
        print(f"    {url}")
        print("[+] Direct local file path:")
        print(f"    {os.path.join(DIRECTORY, 'dashboard.html')}")
        print("=" * 70)
        print("[*] Press Ctrl+C to terminate the server.\n")
        
        if open_browser:
            webbrowser.open(url)
            
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Forensic dashboard server shut down cleanly.")

if __name__ == "__main__":
    start_server(open_browser=False)
