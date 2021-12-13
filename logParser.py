import requests
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET # parsing xml content

def logonEvents():
    useThis = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    path = r'C:\Windows\System32\Winevt\Logs\Security.evtx'
    events = {}
    
    with evtx.Evtx(path) as log:
        for r in log.records():
            event = r.xml()
            xml = ET.fromstring(event)
            eventID = xml.find(f'.//{useThis}EventID').text
            try:
                targetUser = xml[1][5].text
                ip = xml[1][18].text
            except:
                pass

            if eventID == '4624':
                events.update({targetUser : ip})

    for i in events.keys():
        print(f'EventID: 4624, User: {i}, IP: {events.get(i)}')

logonEvents()




##DIFFERENT WAY USING regex... this is not my work btw.
##import Evtx.Evtx as evtx
##import re
##
##path = r'c:\users\student\desktop\security.evtx'
##with evtx.Evtx(path) as log:
##  cnt = 0
##  rslts = {}
##  for r in log.records():
##    if "4624" in r.xml() and "172." in r.xml():
##        cnt += 1
##        ipTemp = re.findall('\<Data\ Name\=\"IpAddress\"\>.*\<\/Data\>',r.xml())
##        ip = re.findall('\d+\.\d+\.\d+\.\d+',ipTemp[0])
##        userTemp = re.findall(r'\<Data\ Name\=\"TargetUserName\"\>.*\<\/Data\>',r.xml())
##        user = re.findall('\>\w+\<',userTemp[0])
##        rslts[ip[0]] = user[0][1:-1]
##        if cnt > 10:
##            break
print(rslts)