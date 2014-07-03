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
import freenet.support.HexUtil;
import freenet.support.Logger;

public final class Hash{
	private static final HashType defaultType = PreferredAlgorithms.preferredMesageDigest;
	private MessageDigest digest;
	
	public Hash(){
		this(defaultType);
	}
	
	public Hash(HashType type){
		try {
			digest = type.get();
		} catch (NoSuchAlgorithmException e) {
			Logger.error(Hash.class, "Check your JVM settings especially the JCE!" + e);
			System.err.println("Check your JVM settings especially the JCE!" + e);
			e.printStackTrace();
			WrapperManager.stop(NodeInitException.EXIT_CRAPPY_JVM);
			throw new RuntimeException();
		} finally {
			defaultType.recycle(digest);
		}
	}
	
	private final byte[] digest(){
		byte[] result = digest.digest();
		return result;
	}
	
	public final byte[] getHash(){
		return digest();
	}
	
	public final byte[] getHash(byte[]... input) {
		addBytes(input);
		return digest();
	}
	
	public final HashResult getHashResult() {
		return new HashResult(defaultType, digest());
	}
	
	public final HashResult getHashResult(byte[]... input){
		addBytes(input);
		return getHashResult();
	}
	
	public final String getHexHash() {
		return HexUtil.bytesToHex(digest());
	}
	
	public final NativeBigInteger getNativeBigIntegerHash(){
		return new NativeBigInteger(1, digest());
	}
	
	public final NativeBigInteger getNativeBigIntegerHash(byte[] data){
		addBytes(data);
		return getNativeBigIntegerHash();
	}
	
	public final void addByte(byte input){
		digest.update(input);
	}

	public final void addBytes(byte[]... input){
		for(byte[] b: input){
			digest.update(b);
		}
	}

	public final void addBytes(ByteBuffer input){
		digest.update(input);
	}
	
	public final void addBytes(byte[] input, int offset, int len){
		digest.update(input, offset, len);
	}
	
	public final boolean verify(byte[] hash, byte[] data){
		digest.reset();
		return MessageDigest.isEqual(hash, getHash());
	}	
	
	public final static boolean verify(HashResult hash, byte[] intput){
		try {
			HashType type = hash.type;
			return verify(hash, new HashResult(type, type.get().digest(intput)));
		} catch (NoSuchAlgorithmException e) {
			Logger.error(Hash.class, "Check your JVM settings especially the JCE!" + e);
			System.err.println("Check your JVM settings especially the JCE!" + e);
			e.printStackTrace();
			WrapperManager.stop(NodeInitException.EXIT_CRAPPY_JVM);
			throw new RuntimeException();
		}
	}
	
	public final static boolean verify(HashResult hash1, HashResult hash2){
		if(hash1.compareTo(hash2) == 0){
			return true;
		}
		return false;
	}
	
}
