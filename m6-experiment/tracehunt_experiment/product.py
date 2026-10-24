"""Portable review assets: Kibana saved searches/dashboard and experiment narrative."""
from .common import *
from .dataset import verify_dataset

def kibana(dataset,out):
    verify_dataset(dataset);scenario=read(Path(dataset)/'scenario.json');out=new_directory(out)
    view='m6-tracehunt-events'
    objects=[{'type':'index-pattern','id':view,'attributes':{'title':','.join(SOURCES),'timeFieldName':'@timestamp','name':'TraceHunt M6'},'references':[]}]
    searches=[('logons','M6 Logons','host.name : "WS-01" and user.name : "lab-user" and event.code : ("4624" or "4625")',['@timestamp','host.name','user.name','event.code','source.ip','winlog.logon.type']),
        ('processes','M6 Processes','host.name : "WS-01" and process.name : "powershell.exe"',['@timestamp','host.name','user.name','process.command_line','process.parent.name']),
        ('network','M6 Network','source.ip : "10.10.10.21"',['@timestamp','source.ip','destination.ip','destination.port','url.original']),
        ('all','M6 All Sources','*',['@timestamp','event.dataset','host.name','event.code'])]
    for ident,title,query,columns in searches:
        objects.append({'type':'search','id':'m6-'+ident,'attributes':{'title':title,
            'description':'Synthetic M3-normalized dataset review. Import requires Kibana validation.',
            'columns':columns,'sort':[['@timestamp','asc']],
            'kibanaSavedObjectMeta':{'searchSourceJSON':canonical({'indexRefName':'kibanaSavedObjectMeta.searchSourceJSON.index','query':{'language':'kuery','query':query},'filter':[]})}},
            'references':[{'name':'kibanaSavedObjectMeta.searchSourceJSON.index','type':'index-pattern','id':view}]})
    panels=[{'panelIndex':str(i+1),'gridData':{'x':24*(i%2),'y':15*(i//2),'w':24,'h':15,'i':str(i+1)},
        'type':'search','panelRefName':'panel_'+str(i+1),'embeddableConfig':{}} for i in range(4)]
    objects.append({'type':'dashboard','id':'m6-tracehunt-dashboard','attributes':{'title':'TraceHunt M6 Scenario Review',
        'description':'Synthetic fixture review, no measured agent repeatability claim.',
        'panelsJSON':canonical(panels),'optionsJSON':canonical({'useMargins':True,'hidePanelTitles':False}),
        'timeRestore':True,'timeFrom':iso(scenario['start']),'timeTo':iso(scenario['end']),'version':1,
        'kibanaSavedObjectMeta':{'searchSourceJSON':canonical({'query':{'language':'kuery','query':'@timestamp < "'+scenario['end']+'"'},'filter':[]})}},
        'references':[{'name':'panel_'+str(i+1),'type':'search','id':'m6-'+x[0]} for i,x in enumerate(searches)]})
    write_rows(out/'m6_saved_objects.ndjson',objects)
    (out/'IMPORT.md').write_text('''# Kibana import verification

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
''',encoding='utf-8')
    return {'dataset_id':read(Path(dataset)/'dataset_manifest.json')['dataset_id'],'objects':len(objects)}


def narrative(result,out):
    kind=result['run_kind'];r0,r1=result['runs']
    label='typed-tool integration smoke' if kind=='typed_api_smoke' else 'exported agent experiment'
    text=f'''# M6 experiment summary

## Executive summary
The evaluation compares two {label} runs with distinct run IDs and the same declared
frozen dataset and configuration. Query Jaccard is {result['query_jaccard']}, retrieved
evidence Jaccard is {result['evidence_jaccard']}, and exact claim Jaccard is
{result['claim_exact_jaccard']}. Verdict agreement is {result['verdict_agreement']}.
These metrics require interpretation alongside coverage and factual-support review.

## Results
Run A: {r0['run_id']} ({r0['verdict']}). Run B: {r1['run_id']} ({r1['verdict']}).
See comparison.csv for per-run counts and differences.json for exact differences.
The current run kind is **{kind}**. A typed_api_smoke result does not measure LLM planning,
M5 verification, independent agent behavior or real collector continuity.

## Limitations
Source query windows and declared collection coverage do not establish real continuous
monitoring. Citation linkage and archived documents do not establish semantic support.
Exact statement matching detects wording differences, not semantic agreement. A single
synthetic sequence does not establish general security accuracy. Ledger truncation or
missing response archives can make comparisons incomplete. Reference hashes are integrity
checks, not cryptographic authenticity. Frozen run IDs alone cannot prove unchanged
external model settings or index state between checks.

## Conclusion
The artifacts permit a reviewer to compare queries and evidence and identify missing
or inconsistent records. Final conclusions about agent repeatability require actual
agent runs, independent setup verification and human review of every factual statement.
'''
    Path(out).write_text(text,encoding='utf-8')
