package freenet.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class HashTest extends TestCase {
	static private HashType[] typeVector = 
		{HashType.MD5, HashType.SHA1, HashType.SHA256, HashType.SHA384, HashType.SHA512};
	static private byte[] abc = { (byte)0x61, (byte)0x62, (byte)0x63 };
	static private String[][] abcVectors =
	    {
	        { "MD5", "900150983cd24fb0d6963f7d28e17f72"},
	        { "SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d" },
	        { "SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	        { "SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
	        { "SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
	    };
	
	//also tests addBytes(byte[]... input) and getHash()
	public void testGetHashByteArrayArray() {
		for(int i = 0; i<typeVector.length; i++){
			HashType type = typeVector[i];
			Hash hash = new Hash(type);
			byte[] toHash = "This string will test hashing.".getBytes();
			try {
				MessageDigest md = MessageDigest.getInstance(type.javaName);
				byte[] mdResult = md.digest(toHash);
				byte[] hashResult = hash.getHash(toHash);
				boolean expectedResult = true;
				boolean sameHash = MessageDigest.isEqual(mdResult, hashResult);
				assertEquals(sameHash, expectedResult);
			} catch (NoSuchAlgorithmException e) {
				throw new Error("Can't load from any provider."+type.javaName);
			}
			
			byte[] abcResult = hash.getHash(abc);
			byte[] expectedABCResult = getABCByteArray(i);
			
			assertEquals(MessageDigest.isEqual(abcResult, expectedABCResult), true);
		}
	}
	
	//tests getHashResult() as well
	public void testGetHashResultHashResultByteArray() {
		HashType type = HashType.SHA256;
		byte[] hashResult = getABCByteArray(2);
		HashResult hash2 = new HashResult(type, hashResult);
		
		Hash hash = new Hash(type);
		HashResult hash1 = hash.getHashResult(abc);
		
		assertEquals(Hash.verify(hash1, hash2), true);
	}
	
	public void testGetHashHex(){
		Hash hash = new Hash(HashType.SHA256);
		hash.addBytes(abc);
		String hexHash = hash.getHexHash();
		
		assertEquals(abcVectors[2][1], hexHash);
	}
	
	public void testGetNativeBIgIntegerHashByteArrayArray(){
		Hash hash = new Hash(HashType.SHA256);
		NativeBigInteger abcVector = new NativeBigInteger(1, getABCByteArray(2));
		NativeBigInteger result = hash.getNativeBigIntegerHash(abc);
		assertEquals(result, abcVector);
		
	}
	
	public void testAddByteByte(){
		byte[] message = "hello world".getBytes();
		Hash hash = new Hash(HashType.SHA256);
		byte[] result = hash.getHash(message);
		
        for (int i = 0; i < message.length; i++)
        {
            hash.addByte(message[i]);
        }
        byte[] result2 = hash.getHash();
        
        assertEquals(MessageDigest.isEqual(result, result2), true);	
	}
	
	public void testAddByteByteArrayIntInt(){
		byte[] message = "hello world".getBytes();
		Hash hash = new Hash(HashType.SHA256);
		byte[] result = hash.getHash(message);
		
		hash.addBytes(message, 0, message.length/2);
		hash.addBytes(message, message.length/2, message.length-message.length/2);
		byte[] result2 = hash.getHash();
        assertEquals(MessageDigest.isEqual(result, result2), true);	
	}

	public void testVerifyByteArrayByteArray() {
		for(int i = 0; i<typeVector.length; i++){
			Hash hash = new Hash(typeVector[i]);
			boolean verified = hash.verify(getABCByteArray(i), abc);
			
			assertEquals(verified, true);
		}
	}

	public void testVerifyHashResultByteArray() {
		HashType type = HashType.SHA256;
		byte[] hashResult = getABCByteArray(2);
		HashResult hash1 = new HashResult(type, hashResult);
		
		assertEquals(Hash.verify(hash1, hashResult), true);
	}
	
	public void testVerifyHashResultHashResult() {
		HashType type = HashType.SHA256;
		byte[] hashResult = getABCByteArray(2);
		HashResult hash1 = new HashResult(type, hashResult);
		HashResult hash2 = new HashResult(type, hashResult);
		
		assertEquals(Hash.verify(hash1, hash2), true);
	}
	
	private byte[] getABCByteArray(int alg){
		return Hex.decode(abcVectors[alg][1]);
	}

}
