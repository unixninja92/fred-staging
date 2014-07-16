/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import freenet.support.Logger;

public enum MACType {
	HMACSHA256(2, "HmacSHA256", KeyType.HMACSHA256),
	Poly1305(4, "POLY1305-AES", 16, KeyType.POLY1305);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String mac;
	public final int ivlen;
	public final KeyType keyType;
	
	private MACType(int bitmask, String mac, KeyType type){
		this.bitmask = bitmask;
		this.mac = mac;
		ivlen = -1;
		keyType = type;
	}
	
	private MACType(int bitmask, String mac, int ivlen, KeyType type){
		this.bitmask = bitmask;
		this.mac = mac;
		this.ivlen = ivlen;
		keyType = type;
	}
	
	public final Mac get(){
		try {
			return Mac.getInstance(mac);
		} catch (NoSuchAlgorithmException e) {
			Logger.error(MACType.class, "Internal error; please report:", e);
		}
		return null;
	}
	
}
