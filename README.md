Private DNS protocol using XPIR
===============================

This project is a proxy that captures and translates DNS requests into XPIR requests and then translates the answers into DNS answers. By using this proxy with a DNS server containing a database of DNS entries it allows a private DNS protocol. 

For more information about XPIR check https://github.com/XPIR-team/XPIR/

*In the current version the proxy is only able to send DNS responses containing one IP address and doesn't handle CNAME records.*

Installation:
=============

Requirements: 
- 64-bits Linux OS: g++>=4.8, gcc>=4.8

Install:
- XPIR (https://github.com/AurelienCasimir/XPIR/archive/master.zip)
- libnet (http://packetfactory.openwall.net/projects/libnet/) 
- libnetfilterqueue (http://www.netfilter.org/projects/libnetfilter_queue/)

Download the project from https://github.com/AurelienCasimir/PrivateDNS/archive/master.zip

Then go to the project folder and use the "make" command.

*Server side:* You only need to install XPIR and take the add_db_entry executable file (found in this project after using make)

Setting up the database:
========================

Each entry is a file in the database folder (XPIR/server/db).
When you want to add an entry to the database put the add_db_entry executable file in XPIR/server and use the following instruction :
```
$ ./add_db_entry <URL> <IP>
```

Usage:
======

Server side:
-----------

In the XPIR folder execute the following commands to start the XPIR server:
```
$ cd server
$ ./build/PIRServer --db-mix -n 65536 -z
```
If you want the server to listen on another port than the default one (=1234), add the option -p <port>


In another terminal (in the XPIR folder) execute these commands to configure the server:
```
$ cd client
$ ./build/PIRClient -r LWE:97:1024:60 -a 1 --dmin 2 --dmax 2 -c
```

Client side:
-----------

In the project folder execute the following command to start the proxy:
```
$ sudo ./proxy.sh <XPIR folder path> <server IP address>
```
If the server is not listening on the default port add <port> at the end of the previous command.


To stop the execution of the proxy:
```
sudo pkill xpir_proxy
```

