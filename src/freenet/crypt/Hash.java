/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

import net.i2p.util.NativeBigInteger;

import freenet.support.HexUtil;

/**
 * The Hash class will generate the hash value of a given set of bytes and also verify that
 * a hash matches a given set of bytes.
 * @author unixninja92
 *
 */
public final class Hash{
	private final HashType type;
	private MessageDigest digest;
	
	/**
	 * Creates an instance of Hash using the specified hashing algorithm
	 * @param type The hashing algorithm to use. 
	 */
	public Hash(HashType type){
		this.type = type;
		digest = type.get();
	}
	
	/**
	 * Generates the hash of all the bytes added using addBytes() methods
	 * @return Hash of all the bytes added since last reset.
	 */
	public final byte[] getHash(){
		byte[] result = digest.digest();
		digest.reset();
		if(type == HashType.TTH){
			digest = type.get();
		}
		return result;
	}
	
	/**
	 * Generates the hash of the given bytes
	 * @param input The bytes to hash
	 * @return The hash of the data
	 */
	public final byte[] getHash(byte[]... input) {
		addBytes(input);
		return getHash();
	}
	
	/**
	 * Generates the hash of all the bytes added using addBytes() methods
	 * @return Hash as HashResult of all the bytes added since last reset.
	 */
	public final HashResult getHashResult() {
		return new HashResult(type, getHash());
	}
	
	/**
	 * Generates the hash of the given bytes
	 * @param input The bytes to hash
	 * @return The hash as HashResult of the data
	 */
	public final HashResult getHashResult(byte[]... input){
		addBytes(input);
		return getHashResult();
	}
	
	/**
	 * Generates the hash of all the bytes added using addBytes() methods
	 * @return Hash as a hex string of all the bytes added since last reset.
	 */
	public final String getHexHash() {
		return HexUtil.bytesToHex(getHash());
	}
	
	/**
	 * Generates the hash of all the bytes added using addBytes() methods
	 * @return Hash as a NativeBigInteger of all the bytes added since last reset.
	 */
	public final NativeBigInteger getNativeBigIntegerHash(){
		return new NativeBigInteger(1, getHash());
	}
	
	/**
	 * Generates the hash of the given bytes
	 * @param input The bytes to hash
	 * @return The hash as NativeBigInteger of the data
	 */
	public final NativeBigInteger getNativeBigIntegerHash(byte[]... data){
		addBytes(data);
		return getNativeBigIntegerHash();
	}
	
	/**
	 * Added byte to be hashed
	 * @param input Byte to be added to hash
	 */
	public final void addByte(byte input){
		digest.update(input);
	}

	/**
	 * Adds byte[]s to be added to hash
	 * @param input The byte[]s to add
	 */
	public final void addBytes(byte[]... input){
		for(byte[] b: input){
			digest.update(b);
		}
	}

	/**
	 * Adds bytes to be hashed
	 * @param input The ByteBuffer to read bytes from to be hashed
	 */
	public final void addBytes(ByteBuffer input){
		digest.update(input);
	}
	
	/**
	 * Adds specified portion of byte[] to be hashed.
	 * @param input The array containing bytes to be hashed
	 * @param offset Where the first byte to hash is
	 * @param len How many bytes after the offset to add to hash.
	 */
	public final void addBytes(byte[] input, int offset, int len){
		digest.update(input, offset, len);
	}
	
	/**
	 * Verify that a hash matches a set of bytes. 
	 * @param hash The hash to be verified
	 * @param data The data to be compared against the hash passed in
	 * @return Returns true if the hash of data matches the passed in. Otherwise returns false.
	 */
	public final boolean verify(byte[] hash, byte[]... data){
		digest.reset();
		addBytes(data);
		return MessageDigest.isEqual(hash, getHash());
	}	
	
	/**
	 * Verifies that a HashResult matches the passed in data.
	 * @param hash The HashResult to verify
	 * @param input The data to check against the HashResult
	 * @return Returns true if HashResult matches the generated HashResult of the data.
	 */
	public final static boolean verify(HashResult hash, byte[] input){
		HashType type = hash.type;
		return verify(hash, new HashResult(type, type.get().digest(input)));
	}
	
	/**
	 * Verifies that the first HashResult matches the second.
	 * @param hash1 The first hash to be compared
	 * @param hash2 The second hash to be compared
	 * @return Returns true if the hashes are the same. If they don't, returns false. 
	 */
	public final static boolean verify(HashResult hash1, HashResult hash2){
		if(hash1.compareTo(hash2) == 0){
			return true;
		}
		return false;
	}
	
}
