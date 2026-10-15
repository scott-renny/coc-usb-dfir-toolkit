"""Conservative analyst leads from acquired exports; never a maliciousness verdict."""
import collections,csv,hashlib,io,json,pathlib,re
MAX_ROWS=5000

def rows(source):
    text=source.read_text(encoding='utf-8-sig')
    if source.suffix.lower()=='.csv':data=list(csv.DictReader(io.StringIO(text)))
    elif source.suffix.lower()=='.jsonl':data=[json.loads(s) for s in text.splitlines() if s.strip()]
    else:
        data=json.loads(text)
        if isinstance(data,dict):
            if isinstance(data.get('Records'),list):data=data['Records']
            elif isinstance(data.get('value'),list):data=data['value']
            else:data=[data]
    if not isinstance(data,list) or len(data)>MAX_ROWS or not all(isinstance(r,dict) for r in data):raise ValueError('Expected up to 5000 structured records')
    return data

def lookup(row,*names):
    mapped={str(k).casefold():v for k,v in row.items()}
    return next((mapped[n.casefold()] for n in names if n.casefold() in mapped),'')

def review(source,profile):
    data=rows(source);leads=[];recognized=0
    for index,row in enumerate(data,1):
        event=str(lookup(row,'EventID','Event ID','event_id')).strip()
        channel=str(lookup(row,'Channel','LogName'));reason=None;provider=None
        if profile=='ExecutionReview':
            if event=='4688' or event=='1' and 'sysmon' in channel.casefold():reason='Process creation event; review subject, parent and command line'
            elif any(k.casefold() in {'executablepath','programname','prefetchfilename','run count','runcount'} for k in row):reason='Execution-related artifact export; artifact semantics and timestamps need review'
            recognized+=int(bool(event) or reason is not None)
        elif profile=='LateralReview':
            recognized+=int(bool(event))
            if event in {'4624','4625','4648','4778','4779','5140','5145','7045','4697','4698'}:
                reason='Authentication, remote-access, share, service or task event; legitimate administration is also possible'
        elif profile=='CloudAudit':
            if 'eventSource' in row and 'eventName' in row:provider='AWS CloudTrail';reason='CloudTrail event'
            elif 'Operation' in row and ('CreationTime' in row or 'RecordType' in row):provider='Microsoft unified audit';reason='Microsoft audit operation'
            elif 'createdDateTime' in row and ('userPrincipalName' in row or 'activityDisplayName' in row):provider='Microsoft Entra';reason='Entra sign-in or audit record'
            elif 'activityDateTime' in row and 'activityDisplayName' in row:provider='Microsoft Entra';reason='Entra directory audit record'
            recognized+=int(provider is not None)
        if reason:
            # Retain scalar and nested metadata as bounded excerpts, never HTML or commands.
            selected={str(k)[:128]:json.dumps(v,ensure_ascii=False)[:2048] for k,v in list(row.items())[:80]}
            stamp=lookup(row,'Timestamp','TimeCreated','TimeCreatedUtc','eventTime','CreationTime','createdDateTime','activityDateTime')
            leads.append(dict(row=index,reason=reason,provider=provider,timestamp_as_exported=str(stamp)[:128],record=selected))
    if not recognized:raise ValueError('No recognized export schema or event fields; coverage not established')
    return dict(records_examined=len(data),recognized_records=recognized,leads=leads,limitations=['Leads are not detections or proof of compromise. Original time zones and clock uncertainty are preserved; no automatic temporal attribution.','Nested values and long fields are excerpts. Record numbers refer to parsed data rows, not physical lines.','Native EVTX and binary artifacts must first use the existing parsers. Cloud audit review uses supplied exports only; no cloud login or API calls.'])

def ransomware(source,out):
    data=source.read_bytes()
    note=bool(re.search(r'(readme|recover|decrypt|restore|ransom)',source.name,re.I)) and source.suffix.lower() in {'.txt','.html','.htm','.md'}
    # Entropy is only a descriptive sample statistic; compressed files can be high too.
    import math
    sample=data[:65536];counts=collections.Counter(sample)
    entropy=-sum((n/len(sample))*math.log2(n/len(sample)) for n in counts.values()) if sample else 0
    return dict(filename=source.name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),sample_bytes=len(sample),sample_entropy_bits_per_byte=round(entropy,4),possible_note_filename=note,note_text_excerpt=data[:65536].decode('utf-8',errors='replace') if note else None,limitations=['Filename and entropy are descriptive clues, not ransomware detection or proof of encryption.','No decryption, renaming, deletion, containment or recovery is attempted. Preserve originals and review backups separately.'])
