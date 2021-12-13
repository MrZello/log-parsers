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