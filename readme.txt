This script parses windows security logs for windows logon events (4624)
and prints any usernames and source network address pairings.  
It also checks for any duplicate entries or entires that do not contain 
a username or source network address.

pip3 install python-evtx