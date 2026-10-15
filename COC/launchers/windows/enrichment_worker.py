"""Fixed offline parser operations. Never executes or opens extracted content."""
import argparse,configparser,hashlib,importlib.util,json,os,pathlib,socket,sys

PROFILES=['URLs','MSG','Decode','ExecutionReview','LateralReview','CloudAudit','RansomwareTriage']

def no_external(event,args):
    if event in {'socket.__new__','socket.connect','socket.connect_ex','socket.getaddrinfo','socket.gethostbyname','socket.gethostbyaddr','socket.sendto','socket.bind','subprocess.Popen','os.system','os.startfile'}:
        raise PermissionError('External communication or execution is disabled in this worker')

def configure(root):
    sys.path.insert(0,str(root/'COC/tools/windows/EnrichmentPackages'))
    sys.path.append(str(root/'COC/tools/windows/EnrichmentPackages/setuptools/_vendor'))
    os.environ['UNFURL_REMOTE_LOOKUPS']='false'
    sys.addaudithook(no_external)

def url_review(source,out):
    from unfurl import core
    # Do not inherit user configuration, API keys, or remote lookup preferences.
    core.load_config=lambda:configparser.ConfigParser()
    lines=source.read_text(encoding='utf-8-sig').splitlines()
    values=[s.strip() for s in lines if s.strip()]
    if not values or len(values)>20:raise ValueError('Select 1-20 URL lines')
    records=[]
    for value in values:
        if len(value)>4096 or not value.lower().startswith(('http://','https://')):raise ValueError('Expected HTTP(S) URL text, at most 4096 characters')
        u=core.Unfurl(remote_lookups=False);u.node_limit=200
        u.add_to_queue(data_type='url',key=None,value=value);u.parse_queue()
        if not u.queue.empty():raise ValueError('URL expansion node cap reached; analysis incomplete')
        records.append(dict(input=value,graph=u.generate_json()))
    return dict(records=records,remote_lookups=False,limitations=['URL interpretation does not establish maliciousness. No URL was visited. Optional parsers may require uninstalled extras.'])

def msg_review(source,out):
    import extract_msg
    with extract_msg.openMsg(str(source),delayAttachments=True) as msg:
        if not hasattr(msg,'subject'):raise ValueError('Unsupported MSG object type')
        record={key:str(getattr(msg,key,None) or '')[:65536] for key in ['subject','sender','to','cc','date','messageId']}
        record['body_excerpt']=str(getattr(msg,'body',None) or '')[:65536]
        attachments=msg.attachments
        if len(attachments)>20:raise ValueError('MSG exceeds 20 attachments')
        total=0;items=[]
        for index,attachment in enumerate(attachments):
            data=attachment.data
            if not isinstance(data,bytes):
                items.append(dict(index=index,status='unsupported',reason='Embedded MSG or non-byte attachment; not recursively opened'));continue
            total+=len(data)
            if len(data)>8*1024**2 or total>16*1024**2:raise ValueError('Attachment byte limit reached')
            target=out/f'attachment-{index:03d}.bin'
            with target.open('xb') as f:f.write(data)
            items.append(dict(index=index,original_filename=str(attachment.longFilename or attachment.shortFilename or '')[:1024],artifact=target.name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),status='extracted'))
        return dict(message=record,attachments=items,limitations=['Body is a text excerpt; formatting and encrypted or signed mail are not validated.','Attachments retain neutral .bin names and are never opened. Embedded messages are unsupported.'])

def decode(source,out):
    import base64,binascii,re
    from refinery.units.encoding.b64 import b64
    from refinery.units.encoding.hex import hex as hex_unit
    value=source.read_bytes().strip()
    if len(value)>1024**2:raise ValueError('Encoded input exceeds 1 MiB')
    compact=re.sub(rb'\s+',b'',value)
    # Strict standard encodings only; never arbitrary recipes, eval, or execution.
    results=[]
    for label,unit,validator in [('base64',b64,lambda:base64.b64decode(compact,validate=True)),('hex',hex_unit,lambda:bytes.fromhex(compact.decode('ascii')))]:
        try:expected=validator()
        except (ValueError,UnicodeError,binascii.Error):continue
        if not expected:continue
        data=bytes(compact | unit())
        if data!=expected:raise ValueError('Independent decode mismatch')
        dest=out/(label+'-decoded.bin')
        with dest.open('xb') as f:f.write(data)
        results.append(dict(encoding=label,artifact=dest.name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
    if not results:raise ValueError('No strict standard base64 or hex decoding applies')
    return dict(results=results,limitations=['Decoded bytes are untrusted data, never executed. No automatic recursive decoding or decompression.'])

def main():
    p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--profile',choices=PROFILES,required=True);p.add_argument('--source',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    root=pathlib.Path(a.toolkit).resolve();source=pathlib.Path(a.source);out=pathlib.Path(a.output)
    if source.stat().st_size>16*1024**2:raise ValueError('Worker input exceeds 16 MiB')
    configure(root)
    if a.profile in ['ExecutionReview','LateralReview','CloudAudit','RansomwareTriage']:
        spec=importlib.util.spec_from_file_location('coc_case_review',pathlib.Path(__file__).with_name('case_review.py'));review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)
        result=review.ransomware(source,out) if a.profile=='RansomwareTriage' else review.review(source,a.profile)
    else:result={'URLs':url_review,'MSG':msg_review,'Decode':decode}[a.profile](source,out)
    result['status']='PARTIAL' if any(x.get('status')=='unsupported' for x in result.get('attachments',[])) else 'COMPLETE'
    encoded=json.dumps(result,indent=2,ensure_ascii=False)
    if len(encoded.encode('utf-8'))>4*1024**2:raise ValueError('Result exceeds 4 MiB')
    (out/'result.json').write_text(encoded,encoding='utf-8')
    return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
