Exfil Framework
=====
The Exfil Framework is a library for the detection of file uploads in TCP connections. The Exfil Framework can detect file uploads in 
most TCP sessions including sessions that have encrypted payloads (SSH, HTTPS). 

Summary
---------
The Exfil framework detects file uploads by monitoring the upstream byte rate of a connection. When the upstream byte rate of 
a connection increases beyond a threshold (defined in main.bro), the script begins counting bytes. When the upstream byte 
rate returns below the threshold or when the connection ends, the byte counting stops. If the byte count is above a threshold (defaults at 64 K)
a Notice is issued that includes the byte count of the burst which corresponds to the size of the file that was transferred.

Upstream TCP byte rate in file transfer
----------
```
          |
          |
          |    __________
byte rate |   /          |
          |  /           |
          |_/            |____
          |____________________
                  time
```
Upstream TCP byte rate in non-file transfer
---------
```
          |
          |
          |   
byte rate |   
          |  
          |_/\_______/\________
          |____________________
                  time
```
Implementation
---------
The Exfil framework contains four Bro scripts:

1. **main.bro** - The script that drives the Exfil analyzer. You probably do not want to edit this file.
2. **app-exfil-conn.bro** - The script that attaches the Exfil analyzer to connections. You will want to edit the redefs exported by this script to choose which connections get monitored for file uploads. **Note:** Start small. If this script is attached to a lot of connections, it may negatively impact the amount of traffic your Bro sensor can process.
3. **app-exfil-after-hours.bro** - This is a policy script that issues a Notice if a file upload is detected after the business hours of your organization. You will want to edit the redefs exported by this file to define the appropriate business hours of your organization.
4. **__load__.bro** - This file allows the Exfil Framework to be loaded in Bro as a folder rather than each script individually. For instance if the framework files are located in a folder called "exfil_framework" the __load__.bro file allows you to add "@load exfil_framework/" to your local.bro and all the necessary files will be loaded when Bro starts.


Quick Start
------------
These instructions will guide you through the installation of the Exfil Framework on your Bro sensor.

* Clone this repository to the "site" folder of your Bro instance
```
git clone https://github.com/reservoirlabs/bro-scripts.git
```
* Enable the Exfil framework by adding the following line to your local.bro:
```
@load bro-scripts/exfil-detection-framework
```
* Redefine networks monitored for exfil in your local.bro:
```
redef Exfil::watched_subnets_conn = [x.x.x.x, y.y.y.y]; 
```
* Redefine the business hour of your network in your local.bro (start_time and end_time must be specified on 24 hour clock):
```
redef Exfil::hours = [ $start_time=x, $end_time=y ];
```
