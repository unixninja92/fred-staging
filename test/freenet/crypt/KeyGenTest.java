package freenet.crypt;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class KeyGenTest extends TestCase {
	private int trueLength = 16;
	private int falseLength = -1;
	private KeyType[] keyTypes = KeyType.values();
	private KeyPairType[] trueKeyPairTypes = {KeyPairType.ECP256, 
			KeyPairType.ECP384, KeyPairType.ECP512};
	private KeyPairType falseKeyPairType = KeyPairType.DSA;
	
	public void testGenKeyPair() {
		for(KeyPairType type: trueKeyPairTypes){
			try {
				assertNotNull("KeyPairType: "+type.name(),KeyGen.genKeyPair(type));
			} catch (UnsupportedTypeException e) {
				fail("UnsupportedTypeException thrown");
			}
		}
	}
	
	public void testGenKeyPairDSAInput() {
		boolean throwException = false;
		try{
			KeyGen.genKeyPair(falseKeyPairType);
		} catch(UnsupportedTypeException e){
			throwException = true;
		}
		assertTrue(throwException);
	}
	
	public void testGenKeyPairNullInput() {
		boolean throwException = false;
		try{
			KeyGen.genKeyPair(null);
		} catch(NullPointerException e){
			throwException = true;
		} catch (UnsupportedTypeException e) {
			fail("UnsupportedTypeException thrown");
		}
		assertTrue(throwException);
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
			assertNotNull("KeyType: "+type.name(), KeyGen.genSecretKey(type));
		}
	}
	
	public void testGenSecretKeyKeySize() {
		for(KeyType type: keyTypes){
			byte[] key = KeyGen.genSecretKey(type).getEncoded();
			assertEquals("KeyType: "+type.name(), type.keySize >> 3, key.length);
		}
	}
	
	public void testGenSecretKeyNullInput() {
		boolean throwException = false;
		try{
			KeyGen.genSecretKey(null);
		} catch(NullPointerException e){
			throwException = true;
		}
		assertTrue(throwException);
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
