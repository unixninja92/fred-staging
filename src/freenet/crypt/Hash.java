/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.node.NodeInitException;
import freenet.support.Logger;

public class Hash{
	private static final HashType defaultType = PreferredAlgorithms.preferredMesageDigest;
	
	public static HashResult hash(byte[] data){
		try {
			MessageDigest digest = defaultType.get();
			byte[] result = defaultType.get().digest(data);
			SHA256.returnMessageDigest(digest);
			return new HashResult(defaultType, result);
		} catch (NoSuchAlgorithmException e) {
			Logger.error(Hash.class, "Check your JVM settings especially the JCE!" + e);
			System.err.println("Check your JVM settings especially the JCE!" + e);
			e.printStackTrace();
		}
		WrapperManager.stop(NodeInitException.EXIT_CRAPPY_JVM);
		throw new RuntimeException();
	}
	
	public static boolean verify(byte[] data, HashResult hash){
		if(hash.compareTo(hash(data)) == 0){
			return true;
		}
		return false;
	}
	
	public static boolean verify(HashResult hash1, HashResult hash2){
		if(hash1.compareTo(hash2) == 0){
			return true;
		}
		return false;
	}
	
}
