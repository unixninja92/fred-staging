/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import freenet.support.Logger;

public enum SigType{
	@Deprecated
	DSA(1),
	ECDSAP256(2, KeyPairType.ECP256, "SHA256withECDSA", 91, 72),
	ECDSAP384(4, KeyPairType.ECP384, "SHA384withECDSA", 120, 104),
	ECDSAP512(8, KeyPairType.ECP521, "SHA512withECDSA", 158, 139);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final KeyPairType keyType;
	/** Name for Signature purposes. Can contain dashes. */
	public final String algName;
    /** Expected size of a DER encoded pubkey in bytes */
	public final int modulusSize;
    /** Maximum (padded) size of a DER-encoded signature (network-format) */
	public final int maxSigSize;
	
	SigType(int bitmask){
		this.bitmask = bitmask;
		this.keyType = null;
		this.algName = this.name();
		modulusSize = -1;
		maxSigSize = -1;
	}
	
	SigType(int bitmask, KeyPairType curve, String alg, int modulus, int maxSize){
		this.bitmask = bitmask;
		keyType = curve;
		algName = alg;
		modulusSize = modulus;
		maxSigSize = maxSize;
	}
	
	public Signature get(){
		try {
			return Signature.getInstance(algName);
		} catch (NoSuchAlgorithmException e) {
			Logger.error(SigType.class, "Internal error; please report:", e);
		}
		return null;
	}
	
	public DSASignature get(String sig) throws UnsupportedTypeException{
		if(this != DSA){
			throw new UnsupportedTypeException(this);
		}
		return new DSASignature(sig);
	}
	
	public DSASignature get(InputStream in) throws IOException, UnsupportedTypeException{
		if(this != DSA){
			throw new UnsupportedTypeException(this);
		}
		return new DSASignature(in);
	}
	
	public DSASignature get(BigInteger r, BigInteger s) throws UnsupportedTypeException{
		if(this != DSA){
			throw new UnsupportedTypeException(this);
		}
		return new DSASignature(r, s);
	}
	
}
