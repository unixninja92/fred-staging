package freenet.crypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public enum MACType {
	HMACSHA1(1, "HMACSHA1", "SHA1"),
	HMACSHA256(2, "HmacSHA256", "SHA256");
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String mac;
	/** Name for MessageDigest purposes. Can contain dashes. */
	public final HashType hash;
	
	MACType(int bitmask, String mac, String hash){
		this.bitmask = bitmask;
		this.mac = mac;
		this.hash = this.hash.valueOf(hash);
	}
	
	public Mac get() throws NoSuchAlgorithmException{
		return Mac.getInstance(mac, PreferredAlgorithms.hmacProvider);
	}

}
