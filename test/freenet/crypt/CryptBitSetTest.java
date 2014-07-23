package freenet.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.BitSet;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class CryptBitSetTest extends TestCase {
	private static final CryptBitSetType[] cipherTypes = CryptBitSetType.values();
	
	private static final byte[] ivPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
			+ "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
			+ "f69f2445df4f9b17ad2b417be66c3710");
	
	private static final byte[][] plainText =
		{ Hex.decode("0123456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef"),
		  Hex.decode("0123456789abcdef1123456789abcdef"), 
		  ivPlainText, ivPlainText, ivPlainText, ivPlainText};
	
	private static final byte[][] keys = 
		{ Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
		  Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
		  Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  Hex.decode("8c123cffb0297a71ae8388109a6527dd"),
		  Hex.decode("a63add96a3d5975e2dad2f904ff584a32920e8aa54263254161362d1fb785790")};
	private static final byte[][] ivs = 
		{ null,
		  null,
		  Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		  Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		  Hex.decode("73c3c8df749084bb"),
		  Hex.decode("7b471cf26ee479fb")};
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public void testSuccessfulRoundTripByteArray() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}
			byte[] ciphertext = crypt.encrypt(plainText[i]);
			
			byte[] decipheredtext = crypt.decrypt(ciphertext);
			assertTrue("CryptBitSetType: "+type.name(), MessageDigest.isEqual(plainText[i], decipheredtext));
		}
	}
	
	public void testSuccessfulRoundTripByteArrayReset() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}
			crypt.encrypt(plainText[i]);
			byte[] ciphertext = crypt.encrypt(plainText[i]);
			crypt.encrypt(plainText[i]);
			
			byte[] decipheredtext = crypt.decrypt(ciphertext);
			assertTrue("CryptBitSetType: "+type.name(), MessageDigest.isEqual(plainText[i], decipheredtext));
		}
	}
	
	public void testSuccessfulRoundTripByteArrayNewInstance() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}
			crypt.encrypt(plainText[i]);
			byte[] ciphertext = crypt.encrypt(plainText[i]);
			crypt.encrypt(plainText[i]);
			
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}
			byte[] decipheredtext = crypt.decrypt(ciphertext);
			assertTrue("CryptBitSetType: "+type.name(), MessageDigest.isEqual(plainText[i], decipheredtext));
		}
	}
	
	public void testSuccessfulRoundTripBitSet() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}
			BitSet plaintext = BitSet.valueOf(plainText[i]);
			System.out.println(Hex.toHexString(plaintext.toByteArray()));
			BitSet ciphertext = crypt.encrypt(plaintext);
			BitSet decipheredtext = crypt.decrypt(ciphertext);
			System.out.println(Hex.toHexString(decipheredtext.toByteArray()));
			assertTrue("CryptBitSetType: "+type.name(), plaintext.equals(decipheredtext));
		}
	}
	
	public void testEncryptByteArrayNullInput(){
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				crypt.encrypt(nullArray);
			}catch(NullPointerException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(), throwNull);
		}
	}

	public void testEncryptBitSetNullInput(){
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			BitSet nullSet = null;
			try{
				crypt.encrypt(nullSet);
			}catch(NullPointerException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(), throwNull);
		}
	}

	public void testEncryptByteArrayIntIntNullInput() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				crypt.encrypt(nullArray, 0, plainText[i].length);
			}catch(NullPointerException | IllegalArgumentException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testEncryptByteArrayIntIntOffsetOutOfBounds() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			try{
				crypt.encrypt(plainText[i], -3, plainText[i].length-3);
			}catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testEncryptByteArrayIntIntLengthOutOfBounds() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			try{
				crypt.encrypt(plainText[i], 0, plainText[i].length+3);
			}catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testDecryptByteArrayNullInput(){
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				crypt.decrypt(nullArray);
			}catch(NullPointerException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(), throwNull);
		}
	}

	public void testDecryptBitSetNullInput(){
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			BitSet nullSet = null;
			try{
				crypt.decrypt(nullSet);
			}catch(NullPointerException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(), throwNull);
		}
	}

	public void testDecryptByteArrayIntIntNullInput() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				crypt.decrypt(nullArray, 0, plainText[i].length);
			}catch(NullPointerException | IllegalArgumentException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testDecryptByteArrayIntIntOffsetOutOfBounds() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			try{
				crypt.decrypt(plainText[i], -3, plainText[i].length-3);
			}catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testDecryptByteArrayIntIntLengthOutOfBounds() {
		for(int i = 0; i < cipherTypes.length; i++){
			CryptBitSetType type = cipherTypes[i];
			CryptBitSet crypt;
			if(ivs[i] == null){
				crypt = new CryptBitSet(type, keys[i]);
			} else {
				crypt = new CryptBitSet(type, keys[i], ivs[i]);
			}

			boolean throwNull = false;
			try{
				crypt.decrypt(plainText[i], 0, plainText[i].length+3);
			}catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){
				throwNull = true;
			}

			assertTrue("CryptBitSetType: "+type.name(),  throwNull);
		} 
	}

	public void testGetIV() {
		int i = 4;
		CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
		assertTrue(MessageDigest.isEqual(crypt.getIV().getIV(), ivs[i]));
	}

	public void testSetIVIvParameterSpec() {
		try {
			int i = 4;
			CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
			crypt.genIV();
			crypt.setIV(new IvParameterSpec(ivs[i]));
			assertTrue(MessageDigest.isEqual(ivs[i], crypt.getIV().getIV()));
		} catch (InvalidAlgorithmParameterException e) {
			fail("InvalidAlgorithmParameterException thrown");
		}
	}

	public void testSetIVIvParameterSpecNullInput() {
		boolean throwNull = false;
		IvParameterSpec nullInput = null;
		try{
			int i = 4;
			CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
			crypt.setIV(nullInput);
		} catch(InvalidAlgorithmParameterException e){
			throwNull = true;
		}
		assertTrue(throwNull);
	}

	public void testSetIVIvParameterSpecUnsupportedTypeException() {
		boolean throwNull = false;
		try{
			int i = 0;
			CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i]);
			crypt.setIV(new IvParameterSpec(ivs[4]));
		} catch(UnsupportedTypeException e){
			throwNull = true;
		} catch (InvalidAlgorithmParameterException e) {
			fail("GeneralSecurityException thrown");
		}
		assertTrue(throwNull);
	}

	public void testGenIV() {
		int i = 4;
		CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
		assertNotNull(crypt.genIV());
	}
	
	public void testGenIVLength() {
		int i = 4;
		CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
		assertEquals(crypt.genIV().length, cipherTypes[i].ivSize);
	}
	
	public void testGenIVUnsupportedTypeException() {
		boolean throwNull = false;
		try{
			int i = 1;
			CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i]);
			crypt.genIV();
		} catch(UnsupportedTypeException e){
			throwNull = true;
		}
		assertTrue(throwNull);
	}

}
