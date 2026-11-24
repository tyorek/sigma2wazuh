#!/usr/bin/env python3
"""P6 pipeline test, run on the siem as root: send four synthetic Windows events (computer P6-TEST) in the agent's
eventchannel wire format into analysisd's queue. Expected alerts: 101129 Kerberos RC4 ticket, 101079 AS-REP roasting,
101041 Security log cleared, 101216 PsExec service install (IDs as of the 2026-11-24 build). They are test events,
not real activity."""
import socket, json, time
from xml.sax.saxutils import escape

def ev(channel, provider, eid, data):
    d = "".join("<Data Name='%s'>%s</Data>" % (k, escape(v)) for k, v in data.items())
    x = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='%s'/>"
         "<EventID>%d</EventID><Version>0</Version><Level>0</Level><Task>0</Task><Opcode>0</Opcode>"
         "<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-24T05:55:00.000000000Z'/>"
         "<EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>%s</Channel>"
         "<Computer>P6-TEST</Computer><Security/></System><EventData>%s</EventData></Event>") % (provider, eid, channel, d)
    return json.dumps({"Message": "P6 Sigma pipeline test event, not real", "Event": x})

evs = [ev("Security", "Microsoft-Windows-Security-Auditing", 4769, {"TargetUserName": "labadmin@HOME.ARPA", "ServiceName": "svc_sql", "TicketOptions": "0x40810000", "TicketEncryptionType": "0x17", "IpAddress": "::ffff:192.168.20.50"}),
       ev("Security", "Microsoft-Windows-Security-Auditing", 4768, {"TargetUserName": "svc_backup", "ServiceName": "krbtgt", "TicketEncryptionType": "0x17", "PreAuthType": "0"}),
       ev("Security", "Microsoft-Windows-Eventlog", 1102, {"SubjectUserName": "labadmin"}),
       ev("System", "Service Control Manager", 7045, {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"})]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
for e in evs:
    s.send(("f:EventChannel:" + e).encode())
    time.sleep(0.3)
print("sent", len(evs))
