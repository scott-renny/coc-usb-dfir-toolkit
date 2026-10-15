"""Fixed third-party parser entry points using isolated, manifest-listed wheels."""
import argparse,pathlib,sys,runpy,json
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'COC/tools/windows/InvestigationPackages'))
def main():
    p=argparse.ArgumentParser();p.add_argument('--tool',choices=['SQLite','SQLiteCarve','RDP','PST','Memory','Versions'],required=True);p.add_argument('--input');p.add_argument('--output');a=p.parse_args()
    if a.tool=='Versions':
        import pypff,PIL,sqlite_dissect
        print(json.dumps(dict(libpff=pypff.get_version(),pillow=PIL.__version__,sqlite_dissect='1.0.0')));return
    source=pathlib.Path(a.input);out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=True)
    if a.tool in ['SQLite','SQLiteCarve']:
        from sqlite_dissect.entrypoint import cli
        # Strict defaults, no database writes and no automatic carving.
        sys.argv=['sqlite_dissect',str(source),'-d',str(out),'-e','csv','-s','-t']
        if a.tool=='SQLiteCarve':sys.argv+=['-c','-f']
        cli()
    elif a.tool=='RDP':
        sys.argv=['bmc-tools','-s',str(source),'-d',str(out),'-c','1000']
        runpy.run_path(str(ROOT/'COC/tools/offline/bmc-tools/bmc-tools.py'),run_name='__main__')
    elif a.tool=='Memory':
        from volatility3.cli import main as volmain
        sys.argv=['vol','--offline','--cache-path',str(out/'symbol-cache'),'-s',str(ROOT/'COC/symbols/windows/symbols'),'-r','json','-f',str(source),'windows.pslist'];volmain()
    elif a.tool=='PST':
        import pypff
        store=pypff.file();store.open(str(source));messages=[];pending=[store.get_root_folder()];limited=False;folder_count=0;attachment_count=0;attachment_bytes=0
        try:
            while pending and len(messages)<500:
                folder=pending.pop();folder_count+=1
                if folder_count>2000:limited=True;break
                for i in range(folder.number_of_sub_messages):
                    if len(messages)>=500:limited=True;break
                    msg=folder.get_sub_message(i)
                    def val(attr):
                        try:
                            v=getattr(msg,attr)
                            if isinstance(v,bytes):v=v.decode('utf-8',errors='replace')
                            return str(v or '')[:65536]
                        except (AttributeError,OSError,RuntimeError):return ''
                    entry=dict(subject=val('subject'),sender_name=val('sender_name'),headers=val('transport_headers'),plain_text=val('plain_text_body'),attachments=int(msg.number_of_attachments),extracted=[])
                    for j in range(min(msg.number_of_attachments,100)):
                        attachment=msg.get_attachment(j)
                        if attachment_count>=100 or attachment.size>25*1024**2 or attachment_bytes+attachment.size>50*1024**2:limited=True;break
                        filename=attachment.long_filename or '';suffix=pathlib.PureWindowsPath(filename).suffix.lower()
                        if suffix not in ['.pdf','.doc','.docm','.docx','.xls','.xlsm','.xlsx','.ppt','.pptm','.pptx','.exe','.dll','.zip','.txt']:suffix='.bin'
                        attachment_count+=1;dest=out/'attachments'/('attachment-'+str(attachment_count)+suffix);dest.parent.mkdir(exist_ok=True)
                        remaining=attachment.size
                        with dest.open('xb') as f:
                            while remaining:
                                chunk=attachment.read_buffer(min(remaining,1024**2))
                                if not chunk:raise ValueError('PST attachment truncated')
                                f.write(chunk);remaining-=len(chunk);attachment_bytes+=len(chunk)
                        import hashlib
                        with dest.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
                        entry['extracted'].append(dict(original_filename=filename,path=dest.relative_to(out).as_posix(),bytes=attachment.size,sha256=digest))
                    if msg.number_of_attachments>100:limited=True
                    messages.append(entry)
                available=max(0,2000-len(pending))
                if folder.number_of_sub_folders>available:limited=True
                for i in range(min(folder.number_of_sub_folders,available)):pending.append(folder.get_sub_folder(i))
            if pending:limited=True
            (out/'pst-messages.json').write_text(json.dumps(dict(messages=messages,limited=limited,scope='Bounded message/header inventory and hashed attachment extraction. Deleted-message recovery is not asserted.'),indent=2),encoding='utf-8')
            if limited:raise SystemExit(2)
        finally:store.close()
if __name__=='__main__':main()
