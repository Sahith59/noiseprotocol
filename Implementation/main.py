#!/usr/bin/env python3
"""
Noise Protocol Secure Chat - Main script

This script provides a convenient way to start either the server or client
for the Noise Protocol Secure Chat application.
"""

import argparse
import sys
import os
from noise_chat_server import NoiseChatServer
from noise_chat_client import NoiseChatClient

def main():
    parser = argparse.ArgumentParser(description='Noise Protocol Secure Chat')
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Server subparser
    server_parser = subparsers.add_parser('server', help='Run in server mode')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind the server to')
    
    # Client subparser
    client_parser = subparsers.add_parser('client', help='Run in client mode')
    client_parser.add_argument('--host', default='localhost', help='Server host to connect to')
    client_parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    client_parser.add_argument('--username', help='Your chat username')
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        print(f"Starting Noise Protocol Secure Chat Server on {args.host}:{args.port}")
        server = NoiseChatServer(host=args.host, port=args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()
            
    elif args.mode == 'client':
        client = NoiseChatClient(host=args.host, port=args.port, username=args.username)
        client.start_chat()
        
    else:
        parser.print_help()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())