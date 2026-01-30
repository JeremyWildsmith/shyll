# Introduction
Your every-day avid Linux enthusiast, researchers and analysts, professional software developers and even their omnipotent Network and System Administrators have all one thing in common: they have connected to a SSH Shell. Some maybe a telnet Shell, or a UART Shell.

A covert back door Shell is yet another Shell, except rather than it existing in plain-sight, it is hidden. The network traffic blends in the background as does the server process on the host machine.

Shyll (Shy-ll) is a covert Shell server that works over a reliable stream protocol established and facilitated using the ICMP IPv4 Protocol. Shyll supports multiple concurrent sessions from multiple remote machines, just like a regular SSH Server, but unlike an SSH Server, Shyll uses only ICMP Echo Requests to communicate between the client and server machine.

# Shyll Blog Posts
This project was used in a blog series that explored malware, reverse engineering and digital forensics. You can read this here:

https://jeremywsmith.substack.com/p/shell-ping-pong-shell-part-1-shyll
