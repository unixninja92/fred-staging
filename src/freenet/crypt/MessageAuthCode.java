package freenet.crypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public class MessageAuthCode {
	private static final MACType defaultType = PreferredAlgorithms.preferredMAC;
	private Mac mac;
	
	public MessageAuthCode(){
		this(defaultType);
	}
	
	public MessageAuthCode(MACType type) {
		try {
			mac = type.get();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
