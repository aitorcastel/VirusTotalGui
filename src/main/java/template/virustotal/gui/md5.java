package template.virustotal.gui;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class md5 {
	/**
	 * it calculates the md5sum
	 * 
	 * @param url file url
	 * @return md5sum
	 */
	public static String getMD5Sum(URL url) {
		MessageDigest digest = null;
				
		try {
			digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
			
		byte[] buffer = new byte[8192];
		int read = 0;
		String output = "";

		InputStream is = null;
		
		try {
			is = url.openStream();

			while( (read = is.read(buffer)) > 0) {
				digest.update(buffer, 0, read);
			}		
			byte[] md5sum = digest.digest();
			BigInteger bigInt = new BigInteger(1, md5sum);
			output = bigInt.toString(16);
		}
		catch(IOException e) {
			e.printStackTrace();
		} finally {
			try {
				is.close();
			} catch(IOException e) {
				e.printStackTrace();
			}
		}
			
		return output;
	}
	
	public static void main (String[] s) throws MalformedURLException{
		System.out.println(getMD5Sum(new URL("http://www.x.x")));
	}
}