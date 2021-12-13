Using python, write a script that will parse windows security logs
for windows logon events (4624) and print to the user any usernames
and source network address pairings.  It should not print duplicate
entries or entires that do not contain a username or source network address.

pip3 install python-evtx