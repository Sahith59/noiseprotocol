#!/usr/bin/env python3
"""
Launcher script for Noise Protocol Chat with Web UI
"""
import os
import sys
import subprocess

def main():
    # Get current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to the server script
    server_script = os.path.join(current_dir, 'noiseprotocol', 'Implementation', 'noise_chat_server.py')
    
    # Path to the web UI
    web_ui_script = os.path.join(current_dir, 'web_ui', 'app.py')
    
    print(f"Starting Noise Chat Server from: {server_script}")
    print(f"Starting Web UI from: {web_ui_script}")
    
    # Start the chat server
    server_process = subprocess.Popen([sys.executable, server_script])
    
    # Start the web UI
    try:
        subprocess.run([sys.executable, web_ui_script])
    finally:
        # Make sure to terminate the server when the web UI exits
        print("Shutting down Noise Chat Server...")
        server_process.terminate()

if __name__ == "__main__":
    main()