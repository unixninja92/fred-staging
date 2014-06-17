package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

public class MessageAuthCode {
	private static final MACType defaultType = PreferredAlgorithms.preferredMAC;
	private Mac mac;
	private SecretKeySpec keySpec;
	
	public MessageAuthCode(byte[] cryptoKey){
		this(defaultType, cryptoKey);
	}
	
	public MessageAuthCode(MACType type, byte[] cryptoKey) {
		try {
			mac = type.get();
			keySpec = new SecretKeySpec(cryptoKey, type.mac);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addByte(byte input){
		mac.update(input);
	}
	
	public void addBytes(byte[]... input){
		for(byte[] b: input){
			mac.update(b);
		}
	}
	
	public void addBytes(ByteBuffer input){
		mac.update(input);
	}
	
	public void addBytes(byte[] input, int offset, int len){
		mac.update(input, offset, len);
	}
	
	public byte[] getMAC(){
		return mac.doFinal();
	}
	
	public byte[] getMAC(byte[]... input){
		addBytes(input);
		return mac.doFinal();
	}
	
	public boolean verify(byte[] otherMac){
		return Arrays.areEqual(getMAC(), otherMac);
	}
	
	public boolean verify(byte[] mac1, byte[] mac2){
		return Arrays.areEqual(mac1, mac2);
	}
	
	public boolean verifyData(byte[] otherMac, byte[]... data){
		return Arrays.areEqual(getMAC(data), otherMac);
	}

}
