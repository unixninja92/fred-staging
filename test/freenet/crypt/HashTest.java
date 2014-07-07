package freenet.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
			byte[] expectedABCResult = Hex.decode(abcVectors[i][1]);
			
			assertEquals(MessageDigest.isEqual(abcResult, expectedABCResult), true);
		}
	}

	public void testVerifyByteArrayByteArray() {
		for(int i = 0; i<typeVector.length; i++){
			Hash hash = new Hash(typeVector[i]);
			boolean verified = hash.verify(Hex.decode(abcVectors[i][1]), abc);
			
			assertEquals(verified, true);
		}
	}

	public void testVerifyHashResultByteArray() {
		HashType type = HashType.SHA256;
		byte[] hashResult = Hex.decode(abcVectors[3][1]);
		HashResult hash1 = new HashResult(type, hashResult);
		
		assertEquals(Hash.verify(hash1, hashResult), true);
	}
	
	public void testVerifyHashResultHashResult() {
		HashType type = HashType.SHA256;
		byte[] hashResult = Hex.decode(abcVectors[3][1]);
		HashResult hash1 = new HashResult(type, hashResult);
		HashResult hash2 = new HashResult(type, hashResult);
		
		assertEquals(Hash.verify(hash1, hash2), true);
	}

}
