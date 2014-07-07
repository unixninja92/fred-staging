/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

import net.i2p.util.NativeBigInteger;

import freenet.support.HexUtil;

public final class Hash{
	private static final HashType defaultType = PreferredAlgorithms.preferredMesageDigest;
	private MessageDigest digest;
	
	public Hash(){
		this(defaultType);
	}
	
	public Hash(HashType type){
		try {
			digest = type.get();
		} finally {
			type.recycle(digest);
		}
	}
	
	public final byte[] getHash(){
		return digest.digest();
	}
	
	public final byte[] getHash(byte[]... input) {
		addBytes(input);
		return getHash();
	}
	
	public final HashResult getHashResult() {
		return new HashResult(defaultType, getHash());
	}
	
	public final HashResult getHashResult(byte[]... input){
		addBytes(input);
		return getHashResult();
	}
	
	public final String getHexHash() {
		return HexUtil.bytesToHex(getHash());
	}
	
	public final NativeBigInteger getNativeBigIntegerHash(){
		return new NativeBigInteger(1, getHash());
	}
	
	public final NativeBigInteger getNativeBigIntegerHash(byte[]... data){
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
		addBytes(data);
		return MessageDigest.isEqual(hash, getHash());
	}	
	
	public final static boolean verify(HashResult hash, byte[] intput){
		HashType type = hash.type;
		return verify(hash, new HashResult(type, type.get().digest(intput)));
	}
	
	public final static boolean verify(HashResult hash1, HashResult hash2){
		if(hash1.compareTo(hash2) == 0){
			return true;
		}
		return false;
	}
	
}
