Exfil Framework
=====
The Exfil Framework is a library for the detection of file uploads in TCP connections. The Exfil Framework can detect file uploads in 
most TCP sessions, including ones that are encrypted.

Summary
---------
The Exfil framework detects file uploads by monitoring the upstream byte rate of a connection. When the upstream byte rate of 
a connection increases beyond a threshold (defined in main.bro), the script begins counting bytes. When the the upstream byte 
rate returns below the threshold or when the connection ends, the byte counting is ended and a Notice is issued that includes
the byte count of the burst which corresponds with the size of the file that was transferred. 

Upstream TCP byte rate in file transfer
=====
          |
          |
          |    __________
byte rate |   /          |
          |  /           |
          |_/            |____
          |____________________
                  time

Upstream TCP byte rate in non-file transfer
=====
          |
          |
          |   
byte rate |   
          |  
          |_/\_______/\________
          |____________________
                  time

Implementation
---------
The Exfil framework contains three four different Bro scripts:
1. main.bro - The script that drives the Exfil framework. You probably do not want to edit this file.
2. app-exfil-conn.bro - The script that attaches the Exfil analyzer to connections. You will want to edit this file to choose which connections get
monitored for file uploads. Note: Start small. If this script is attached to a lot of connections, it may negatively impact the amount of traffic 
your Bro sensor can process.
3. app-exfil-after-hours.bro - This is a policy script that issues a Notice if a file upload is detected after the business hours of your organization.
The business hours of your organization can be edited in this file. 



