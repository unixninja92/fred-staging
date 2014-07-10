package freenet.crypt;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class KeyGenTest extends TestCase {
	private int trueLength = 16;
	private int falseLength = -1;
	private KeyType[] keyTypes = KeyType.values();

	public void testGenKeyPair() {
		fail("Not yet implemented");
	}

	public void testGetPublicKey() {
		fail("Not yet implemented");
	}

	public void testGetPublicKeyPair() {
		fail("Not yet implemented");
	}

	public void testGetKeyPairByteArrayByteArray() {
		fail("Not yet implemented");
	}

	public void testGetKeyPairPublicKeyPrivateKey() {
		fail("Not yet implemented");
	}

	public void testGenSecretKey() {
		for(KeyType type: keyTypes){
			
		}
	}

	public void testGetSecretKey() {
		for(KeyType type: keyTypes){
			SecretKey key = KeyGen.genSecretKey(type);
			SecretKey newKey = KeyGen.getSecretKey(key.getEncoded(), type);
			assertTrue("KeyType: "+type.name(),
					Arrays.areEqual(key.getEncoded(), newKey.getEncoded()));
		}
	}

	public void testGenNonceLength() {
		assertEquals(KeyGen.genNonce(trueLength).length, trueLength);
	}
	
	public void testGenNonceNegativeLength() {
		boolean throwException = false;
		try{
			KeyGen.genNonce(falseLength);
		} catch(NegativeArraySizeException e){
			throwException = true;
		}
		assertTrue(throwException);
	}

	public void testGenIV() {
		assertEquals(KeyGen.genIV(trueLength).getIV().length, trueLength);
	}
	
	public void testGenIVNegativeLength() {
		boolean throwException = false;
		try{
			KeyGen.genIV(falseLength);
		} catch(NegativeArraySizeException e){
			throwException = true;
		}
		assertTrue(throwException);
	}
	
	public void testGetIvParameterSpec() {
		fail("Not yet implemented");
	}

}
