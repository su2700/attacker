# Network Payload Generator and Server

A Python-based tool for generating, serving, and listening for network payloads. This tool combines payload generation capabilities with a built-in HTTP server and network listener.

## Features

- Generate custom payloads using msfvenom
- Serve payloads via HTTP server
- Integrated netcat listener for connections
- Support for multiple payload types:
  - Windows Meterpreter (x64/x86)
  - Windows Reverse Shell
  - Linux Reverse Shell
  - Python Reverse Shell
  - And more...

## Prerequisites

- Python 3.x
- Metasploit Framework (for msfvenom)
- Netcat (nc)

## Installation

1. Clone the repository
2. Ensure you have the required dependencies installed:
```bash
brew install netcat
brew install metasploit
```