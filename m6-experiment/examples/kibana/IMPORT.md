# Kibana import verification

Target: M1 Kibana 8.12. Generated saved objects are locally checked JSON only.
Live import, migrations and rendering remain unverified.

1. In an isolated lab, M1 loads normalized/bulk.ndjson and checks every item.
   Fixed M3 IDs use create actions. Conflicts mean the data already exists.
2. Open Stack Management > Saved Objects > Import and import this NDJSON.
   Review existing objects before overwriting or resolving conflicts.
3. Refresh the TraceHunt M6 data view. Confirm all six objects and references resolve.
4. Open the dashboard and confirm the absolute scenario time in Singapore (+08:00).
5. Full source counts: Windows 12, Sysmon 4, Zeek 4. Inside the half-open window:
   Windows 10, Sysmon 2, Zeek 2, total 14.
6. Check eight target failures and one target success. Review other-host and other-server
   decoys rather than assuming every PowerShell or network record belongs to the target.
7. Save screenshots, actual Kibana version and import/check results for the final demo.

If Kibana rejects a schema/migration, recreate the data view and saved searches using
these KQL queries, then export from the team's actual version. Local JSON reference
checks do not count as a successful import. Zeek has no invented user.name/host.name.
