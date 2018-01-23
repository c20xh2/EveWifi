# EveWifi

## Installation

You will need:

    apt-get install aircrack-ng
    pip3 install scapy-python3
    git clone https://github.com/c20xh2/EveWifi


## Usage:

    sudo python3 EveWifi.py
    
When asked, you should send at least 300 deauth packet if you want to disconnect the client for 1 minute (or use 0 for non-stop deauth)

## What is this:

The script will find online access point around you and will let you select client(s) to deauthentificate.
It is also possible to send deauth packets to all clients.

Right now the script will only find "Active" clients, if the target is not showing in the list it's because the client is not currently sending/receiving any data. You can choose to deauth all clients to disconnect idle devices.
## To do:

- Remove aircrack-ng dependency, use iwconfig instead to put interface in monitor mode.
- Add "Deauth all access point" function.
- Split functions and class in files instead of having everything in EveWifi.py
- Add comments to script
- Learn english correctly
 




Use this script on your own equipements, this is for testing only.




