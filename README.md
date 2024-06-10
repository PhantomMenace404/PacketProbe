# PRODIGY_CS_05

# PacketProbe
PacketProbe is a basic network packet analyzer developed in Python using `scapy`. This tool captures and analyzes network packets, displaying information such as source and destination IP addresses, protocols, and payload data.


## Features

- Capture and analyze network packets.
- Display source and destination IP addresses.
- Identify the protocol used (TCP, UDP, ICMP).
- Show source and destination ports.
- View the payload data of packets.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [Ethical Use](#ethical-use)
- [License](#license)

## Prerequisites

- Python 3.x: This program requires Python version 3.x. You can check your Python version by running `python --version` or `python3 --version` in your terminal. If you do not have Python 3.x installed, you can download it from the [official Python website](https://www.python.org/downloads/).

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/PRODIGY_CS_05.git
    cd PRODIGY_CS_05
    ```

2. **Install dependencies**:
    ```bash
    pip install scapy rich
    ```

## Usage

1. **Run the script**:
    ```bash
    sudo python3 packet_probe.py -i <network_interface>
    ```

    Replace `<network_interface>` with the appropriate network interface (e.g., `eth0`, `wlan0`). Note that sudo privileges are required to capture packets.

2. **Interact with the program**:
    - The tool will start capturing packets on the specified network interface.
    - Information about each captured packet will be displayed in a table format.
    - To stop capturing packets, press `Ctrl + C`.

### Example

```plaintext
╭──────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Field                │ Value                                                                                                                         │
├──────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Source IP            │ 127.0.0.1                                                                                                                     │
│ Destination IP       │ 2**.***.***.***.***                                                                                                           │
│ Protocol             │ UDP                                                                                                                           │
│ Source Port          │ 55963                                                                                                                         │
│ Destination Port     │ 1900                                                                                                                          │
│ Payload              │ b'M-SEARCH * HTTP/1.1\r\nHOST: 2**.**.***.**:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST:                                     │
│                      │ urn:dial-multiscreen-org:service:dial:1\r\nUSER-AGENT: Chromium/1**.*.**.** Windows\r\n\r\n'                                  │
╰──────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
