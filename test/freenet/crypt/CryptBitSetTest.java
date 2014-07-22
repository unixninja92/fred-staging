package freenet.crypt;

import java.security.Security;

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
		  Hex.decode("c964b00326e216214f1a68f5b08726081b403c92fe02898664a81f5bbbbf8341fc1"
		  		+ "d04b2c1addfb826cca1eab68131272751b9d6cd536f78059b10b4867dbbd9"),
		  Hex.decode("c2bbcdf27ff500121180e3e078e7e30a412e550fad639080309b996734daf8d5e7d"
		  		+ "c282ec0ccd2e52b477749810ffb450e07581ea46659c9bb728cc72568cd6f"),
		  Hex.decode("20c35193884e15d5e3c404294cf35f423c3af2d451be0775fceee0295e8c8d02423"
		  		+ "d3bc196d4d3cbb298db53236641399abebf704208a4396826980ab4a22e76"),
		  Hex.decode("f3cd67475ba4f50d75108617f901362519e23b811f4dfe34d2065e768445c08dc99"
		  		+ "94000e4ad435b0f8021cedccb0ddd9cd6cee095d17d998a4d84fa2d463885")
		};

	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public void testEncryptByteArray() {
		fail("Not yet implemented");
	}

	public void testEncryptBitSet() {
		fail("Not yet implemented");
	}

	public void testDecryptByteArray() {
		fail("Not yet implemented");
	}

	public void testDecryptBitSet() {
		fail("Not yet implemented");
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
