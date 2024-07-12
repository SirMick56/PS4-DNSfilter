# PS4-DNSfilter

![Windows Terminal](https://img.shields.io/badge/Windows%20Terminal-%234D4D4D.svg?style=for-the-badge&logo=windows-terminal&logoColor=white) ![Debian](https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white)

PS4-DNSfilter is a local DNS service designed to filter URLs for your PlayStation 4 and other devices to prevent unwanted updates when it is connected to the network.

![screenshot2](https://github.com/user-attachments/assets/9a8465da-666a-46d3-9567-44dddf1a60e8)

## Features

- Blocks specific domains to prevent automatic updates.
- Runs on Linux and Windows.
- Allows whitelisting and blacklisting of domains via configuration files.
- Logs blocked domains and requests.
- Provides real-time display of forwarded and blocked requests.
- Supports additional DNS, like Nintendo!

## How to use it

- Launch the program (Windows or Linux, i will call it the "server")
- Go to the network settings of your gaming console.
- Change the primary DNS to the IP address of your server, and remove the secondary DNS.
- You will see the blocked addresses and all unfiltered requests.
  Each new URL will be logged in a CSV file in the server's folder.
  Add the desired address to blacklist.conf or whitelist.conf to block or allow it.
  Note that you will have better NAT results under Windows.

## Prerequisites

- Free network 53 port
