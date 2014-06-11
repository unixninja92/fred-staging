/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.i2p.util.NativeBigInteger;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.node.NodeInitException;
import freenet.support.Logger;

public class Hash{
	private static final HashType defaultType = PreferredAlgorithms.preferredMesageDigest;
	private MessageDigest digest;
	
	public Hash(){
		try {
			MessageDigest digest = defaultType.get();
		} catch (NoSuchAlgorithmException e) {
			Logger.error(Hash.class, "Check your JVM settings especially the JCE!" + e);
			System.err.println("Check your JVM settings especially the JCE!" + e);
			e.printStackTrace();
		}
		WrapperManager.stop(NodeInitException.EXIT_CRAPPY_JVM);
		throw new RuntimeException();
	}
	
	private byte[] digest(){
		byte[] result = digest.digest();
		SHA256.returnMessageDigest(digest);
		return result;
	}
	
	public byte[] getHash(){
		return digest();
	}
	
	public byte[] getHash(byte[] input) {
		addBytes(input);
		return digest();
	}
	
	public HashResult getHashResult() {
		return new HashResult(defaultType, digest());
	}
	
	public HashResult getHashResult(byte[] data){
		addBytes(data);
		return getHashResult();
	}
	
	public NativeBigInteger getNativeBigIntegerHash(){
		return new NativeBigInteger(1, digest());
	}
	
	public NativeBigInteger getNativeBigIntegerHash(byte[] data){
		addBytes(data);
		return getNativeBigIntegerHash();
	}
	
	public void addByte(byte input){
		digest.update(input);
	}

	public void addBytes(byte[] input){
		digest.update(input);
	}

	public void addBytes(ByteBuffer input){
		digest.update(input);
	}
	
	public void addBytes(byte[] input, int offset, int len){
		digest.update(input, offset, len);
	}

	public boolean verify(HashResult hash, byte[] data){
		digest.reset();
		if(hash.compareTo(getHashResult(data)) == 0){
			return true;
		}
		return false;
	}
	
	public boolean verify(byte[] hash, byte[] data){
		digest.reset();
		return Arrays.equals(hash, getHash(data));
	}
	
	public static boolean verify(HashResult hash1, HashResult hash2){
		if(hash1.compareTo(hash2) == 0){
			return true;
		}
		return false;
	}
	
}
