# OSINTUS version 2.2
## Description
This application allows you to get various information about the IP, URL, MAC address, domain, check access to the 
resource in different countries by http, ping, tcp/udp,dns. Checks suspicious files for malicious code.
Tested on Ubuntu 22.04, Kali 2023.2, python 3.10+.

OSINTUS is written entirely in Python, with no dependencies to external libraries.

## Features
* Determine the manufacturer and location by mac address
* Get an IP address report and information about him
* Get information about a file by hash
* Retrieve information about a file
* Detects dangerous IP addresses
* Scan URL and files
___
### Installation method and run
    git clone https://github.com/vomanc/OSINTUS.git
    cd OSINTUS
    python3 osintus.py -h
___
### Requirements
Add API keys:
* IPINFO_TOKEN: https://ipinfo.io/
* VIRUSTOTAL_TOKEN: https://www.virustotal.com
* COMBAIN_TKEN: https://combain.com/
___
### Examples running:
	python3 osintus.py -ip 1.1.1.1
	python3 osintus.py -ipv 1.1.1.1
	python3 osintus.py -udp example.com
	python3 osintus.py -url example.com
	python3 osintus.py -f /home/test_file.js
    python3 osintus.py -hash dbf9ab052e342522ca1...
___
## Author: @vomanc
___
### Tech Stack

* __python3__
___
### Donation
![Bitcoin](https://www.blockchain.com/explorer/_next/static/media/bitcoin.df7c9480.svg) BTC
* bc1q8ymcf78f4qwjlyj9v7q3ujtqm8nm9e3rms3rcq

![Ethereum](https://www.blockchain.com/explorer/_next/static/media/ethereum.57ab686e.svg) ETH
* 0x015a50222160E7EF9d0ED030BA232025234D0f82

![Tether](https://www.blockchain.com/explorer/_next/static/media/usdt.dd7e4bef.svg) USDT
* 0x015a50222160E7EF9d0ED030BA232025234D0f82
---
![WebMoney](https://www.webmoney.ru/favicon-32x32.png)
### WebMoney
* WMZ: Z826298065674
* WME: E786709266824

