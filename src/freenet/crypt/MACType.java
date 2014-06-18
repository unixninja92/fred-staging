package freenet.crypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public enum MACType {
	HMACSHA1(1, "HMACSHA1"),
	HMACSHA256(2, "HmacSHA256"),
	Poly1305(4, "POLY1305-AES", 16);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String mac;
	public final int ivlen;
	
	MACType(int bitmask, String mac){
		this.bitmask = bitmask;
		this.mac = mac;
		ivlen = -1;
	}
	
	MACType(int bitmask, String mac, int ivlen){
		this.bitmask = bitmask;
		this.mac = mac;
		this.ivlen = ivlen;
	}
	
	public final Mac get() throws NoSuchAlgorithmException{
		return Mac.getInstance(mac, PreferredAlgorithms.macProviders.get(mac));
	}
	
}
