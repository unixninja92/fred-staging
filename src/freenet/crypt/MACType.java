package freenet.crypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public enum MACType {
	HMACSHA1(1, "HMACSHA1", false),
	HMACSHA256(2, "HmacSHA256", false),
	Poly1305(4, "POLY1305-AES", true);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String mac;
	public final boolean usesIV;
	
	MACType(int bitmask, String mac, boolean usesIV){
		this.bitmask = bitmask;
		this.mac = mac;
		this.usesIV = usesIV;
	}
	
	public Mac get() throws NoSuchAlgorithmException{
		return Mac.getInstance(mac, PreferredAlgorithms.hmacProvider);
	}
	
}
