package freenet.crypt;

import java.security.GeneralSecurityException;

import javax.crypto.spec.IvParameterSpec;

import junit.framework.TestCase;

import org.bouncycastle.util.encoders.Hex;

public class MessageAuthCodeTest extends TestCase {
	static private final MACType[] types = 
		{ MACType.HMACSHA256, MACType.Poly1305};
	static private final byte[][] keys = 
		{ Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), 
		Hex.decode("95cc0e44d0b79a8856afcae1bec4fe3c01bcb20bfc8b6e03609ddd09f44b060f")};
	static private final byte[][] messages = { "Hi There".getBytes(), new byte[128]};
	static private final IvParameterSpec[] IVs = 
		{ null, new IvParameterSpec(new byte[16])};
	static private final String[] macs = 
		{ "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		"4bb5e21dd13001ed5faccfcfdaf8a854"};

	public void testAddByte() {
		fail("Not yet implemented");
	}

	public void testAddBytesByteBuffer() {
		fail("Not yet implemented");
	}

	public void testAddBytesByteArrayIntInt() {
		fail("Not yet implemented");
	}

	public void testGetMacByteArrayArray() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				byte[] result = mac.genMac(messages[i]);
				assertTrue(MessageAuthCode.verify(result, Hex.decode(macs[i])));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			} catch (UnsupportedTypeException e) {
				fail("UnsupportedTypeException thrown");
			}
		}
	}

	public void testVerify() {
		fail("Not yet implemented");
	}

	public void testVerifyData() {
		fail("Not yet implemented");
	}

	public void testGetKey() {
		fail("Not yet implemented");
	}

	public void testGetEncodedKey() {
		fail("Not yet implemented");
	}

	public void testGetIV() {
		fail("Not yet implemented");
	}

	public void testGetIVSpec() {
		fail("Not yet implemented");
	}

	public void testChangeIVIvParameterSpec() {
		fail("Not yet implemented");
	}

	public void testChangeIVByteArray() {
		fail("Not yet implemented");
	}

	public void testGenIV() {
		fail("Not yet implemented");
	}

}
