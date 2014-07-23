package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.BitSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class CryptBitSetTest extends TestCase {
	private static final CryptBitSetType[] cipherTypes = CryptBitSetType.values();
	private static final byte[][] ecbPlainText = 
		{ Hex.decode("0123456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef"),
		  Hex.decode("0123456789abcdef1123456789abcdef")};
	
	private static final byte[] ivPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
			+ "ae2d8a571e03ac9c9eb76fac45af8e51"
			+ "30c81c46a35ce411e5fbc1191a0a52ef"
			+ "f69f2445df4f9b17ad2b417be66c3710");
	
	private static final byte[][] plainText =
		{ecbPlainText[0], ecbPlainText[1], ivPlainText, ivPlainText, ivPlainText, ivPlainText};
	
	private static final byte[][] keys = 
		{ Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
		  Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
		  Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		  Hex.decode("8c123cffb0297a71ae8388109a6527dd"),
		  Hex.decode("a63add96a3d5975e2dad2f904ff584a32920e8aa54263254161362d1fb785790")
		};
	private static final byte[][] ivs = 
		{ null,
		  null,
		  Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		  Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		  Hex.decode("73c3c8df749084bb"),
		  Hex.decode("7b471cf26ee479fb")
		};
	private static final byte[][] cipherTexts =
		{ Hex.decode("6fcbc68fc938e5f5a7c24d7422f4b5f153257b6fb53e0bca26770497dd65078c"),
		  Hex.decode("a19094ac2740857eea7ccf08d38a7706"),
		  Hex.decode("632a0ff9f4ae612a08999aef6926a8b18aa4b84c49fb7c4702682903dcfec2733bb8c46a5267153f60cb1bd5228f04f5ca58524afda60bd4c7b9323395d554cb"),
		  Hex.decode("68f57208adb97719560311faa1466db3d0cad1d11a9a6541565baf3f539bb9e72079e8f6530618626d40cd761501ce97e30eb38294933d657950ae4036c0227d"),
		  Hex.decode("8a8dee695a0262dea447f6339552d1fbadde760ae647f2b49a2ed67139cdcc308598fb19051e194cf49f616cb76874eb77b754ec72fdc095aa04ba8da70ac164"),
		  Hex.decode("5983d8bd89e882063293740d20a0b89c8806bf5fa8b40bf5b4c6682ee30481bf0e3c80d8776789dc49879bf148c5380f71df257ca5241935486fa67d3eeed797")};

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

	public void testSetIV() {
		fail("Not yet implemented");
	}

	public void testGenIV() {
		fail("Not yet implemented");
	}

	public void testGetIV() {
		fail("Not yet implemented");
	}

}
