package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

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
	static private final byte[][] trueMacs = 
		{ Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
		Hex.decode("4bb5e21dd13001ed5faccfcfdaf8a854")};
	static private final byte[][] falseMacs = 
		{ Hex.decode("4bb5e21dd13001ed5faccfcfdaf8a854881dc200c9833da726e9376c2e32cff7"),
		Hex.decode("881dc200c9833da726e9376c2e32cff7")};

	public void testAddByte() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				
				for (int j = 0; j < messages[i].length; j++){
					mac.addByte(messages[i][j]);
				}
				assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(mac.genMac(), trueMacs[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	@SuppressWarnings("null")
	public void testAddByteNullInput() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				
				boolean throwNull = false;
				Byte nullByte = null;
				try{
					mac.addByte(nullByte);
				}catch(NullPointerException e){
					throwNull = true;
				}
				
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	public void testAddBytesByteBuffer() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				ByteBuffer byteBuffer = ByteBuffer.wrap(messages[i]);
				
				mac.addBytes(byteBuffer);
				assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(mac.genMac(), trueMacs[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testAddBytesByteBufferNullInput() {
		try {
			int i = 0;
			MessageAuthCode mac;
			if(types[i].ivlen != -1){
				mac = new MessageAuthCode(keys[i], IVs[i]);
			} else{
				mac = new MessageAuthCode(types[i], keys[i]);
			}

			boolean throwNull = false;
			ByteBuffer byteBuffer = null;
			try{
				mac.addBytes(byteBuffer);
			}catch(IllegalArgumentException e){
				throwNull = true;
			}

			assertTrue("MACType: "+types[i].name(), throwNull);
		} catch (GeneralSecurityException e) {
			fail("GeneralSecurityException thrown");
		}
	}

	public void testAddBytesByteArrayIntInt() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				mac.addBytes(messages[i], 0, messages[i].length/2);
				mac.addBytes(messages[i], messages[i].length/2, messages[i].length-messages[i].length/2);
				
				assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(mac.genMac(), trueMacs[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testAddBytesByteArrayIntIntNullInput() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				
				boolean throwNull = false;
				byte[] nullArray = null;
				try{
					mac.addBytes(nullArray, 0, messages[i].length);
				}catch(NullPointerException e){
					throwNull = true;
				}
				
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testAddBytesByteArrayIntIntOffsetOutOfBounds() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				
				boolean throwNull = false;
				try{
					mac.addBytes(messages[i], -3, messages[i].length-3);
				}catch(IllegalArgumentException e){
					throwNull = true;
				}
				
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testAddBytesByteArrayIntIntLengthOutOfBounds() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				} else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				
				boolean throwNull = false;
				try{
					mac.addBytes(messages[i], 0, messages[i].length+3);
				}catch(IllegalArgumentException e){
					throwNull = true;
				}
				
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	//tests .genMac() and .addBytes(byte[]...] as well
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
				assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(result, trueMacs[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	public void testGetMacByteArrayArrayReset() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				mac.addBytes(messages[i]);
				byte[] result = mac.genMac(messages[i]);
				assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(result, trueMacs[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testGetMacByteArrayArrayNullInput() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}

				boolean throwNull = false;
				byte[] nullArray = null;
				try{
					mac.genMac(nullArray);
				}catch(NullPointerException e){
					throwNull = true;
				}

				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testGetMacByteArrayArrayNullMatrixElementInput() {
		try {
			MessageAuthCode mac = new MessageAuthCode(keys[1], IVs[1]);				
			boolean throwNull = false;
			byte[][] nullMatrix = {messages[1], null};
			try{
				mac.genMac(nullMatrix);
			}catch(NullPointerException e){
				throwNull = true;
			}

			assertTrue("MACType: "+types[1].name(), throwNull);
		} catch (GeneralSecurityException e) {
			fail("GeneralSecurityException thrown");
		}
	}

	public void testVerify() {
		assertTrue(MessageAuthCode.verify(trueMacs[1], trueMacs[1]));
	}
	
	public void testVerifyFalse() {
		assertFalse(MessageAuthCode.verify(trueMacs[1], falseMacs[1]));
	}
	
	public void testVerifyNullInput1() {
		boolean throwNull = false;
		byte[] nullArray = null;
		try{
			MessageAuthCode.verify(nullArray, trueMacs[1]);
		}catch(NullPointerException e){
			throwNull = true;
		}
		assertTrue(throwNull);
	}
	
	public void testVerifyNullInput2() {
		boolean throwNull = false;
		byte[] nullArray = null;
		try{
			MessageAuthCode.verify(trueMacs[1], nullArray);
		}catch(NullPointerException e){
			throwNull = true;
		}
		assertTrue(throwNull);
	}

	public void testVerifyData() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				assertTrue("MACType: "+types[i].name(), mac.verifyData(trueMacs[i], messages[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testVerifyDataFalse() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				assertFalse("MACType: "+types[i].name(), mac.verifyData(falseMacs[i], messages[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testVerifyDataNullInput1() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				boolean throwNull = false;
				byte[] nullArray = null;
				try{
					mac.verifyData(nullArray, messages[i]);
				}catch(NullPointerException e){
					throwNull = true;
				}
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}
	
	public void testVerifyDataNullInput2() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				boolean throwNull = false;
				byte[] nullArray = null;
				try{
					mac.verifyData(trueMacs[i], nullArray);
				}catch(NullPointerException e){
					throwNull = true;
				}
				assertTrue("MACType: "+types[i].name(), throwNull);
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	public void testGetKey() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				assertTrue("MACType: "+types[i].name(), MessageDigest.isEqual(mac.getKey().getEncoded(), keys[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	public void testGetEncodedKey() {
		for(int i = 0; i < types.length; i++){
			try {
				MessageAuthCode mac;
				if(types[i].ivlen != -1){
					mac = new MessageAuthCode(keys[i], IVs[i]);
				}
				else{
					mac = new MessageAuthCode(types[i], keys[i]);
				}
				assertTrue("MACType: "+types[i].name(), MessageDigest.isEqual(mac.getEncodedKey(), keys[i]));
			} catch (GeneralSecurityException e) {
				fail("GeneralSecurityException thrown");
			}
		}
	}

	public void testGetIV() {
		try {
			MessageAuthCode mac = new MessageAuthCode(keys[1], IVs[1]);
			assertTrue(MessageDigest.isEqual(mac.getIv(), IVs[1].getIV()));
		} catch (GeneralSecurityException e) {
			fail("GeneralSecurityException thrown");
		}
	}
	
	public void testGetIVUnsupportedTypeException() {
		boolean throwNull = false;
		try{
			MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
			mac.getIv();
		} catch(UnsupportedTypeException e){
			throwNull = true;
		} catch (GeneralSecurityException e) {
			fail("GeneralSecurityException thrown");
		}
		assertTrue(throwNull);
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
