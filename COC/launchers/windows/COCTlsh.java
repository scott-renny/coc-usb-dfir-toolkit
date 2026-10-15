import com.trendmicro.tlsh.*;
import java.io.*;
import java.nio.file.*;
/** Fixed local-file similarity helper. Inputs are data, never loaded as code. */
public class COCTlsh {
 public static void main(String[] args) throws Exception {
  if(args.length<1 || args.length>20)throw new IllegalArgumentException("Select 1-20 files");
  Tlsh[] hashes=new Tlsh[args.length];
  for(int i=0;i<args.length;i++){
   Path p=Path.of(args[i]);
   if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)>16*1024*1024)throw new IllegalArgumentException("File scope exceeds limit");
   TlshCreator creator=new TlshCreator();
   try(InputStream stream=Files.newInputStream(p)){byte[] b=new byte[65536];int n;while((n=stream.read(b))!=-1)creator.update(b,0,n);}
   try{hashes[i]=creator.getHash();System.out.println("HASH\t"+i+"\t"+hashes[i].getEncoded());}
   catch(IllegalStateException e){System.out.println("UNSUPPORTED\t"+i+"\tinsufficient length or variation");}
  }
  for(int i=0;i<args.length;i++)for(int j=i+1;j<args.length;j++)if(hashes[i]!=null&&hashes[j]!=null)System.out.println("DIFF\t"+i+"\t"+j+"\t"+hashes[i].totalDiff(hashes[j],true));
 }
}
