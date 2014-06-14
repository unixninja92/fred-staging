package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public enum SigType{
	DSA(1),
	ECDSAP256(2, "secp256r1", "SHA256withECDSA", 91, 72),
	ECDSAP384(4, "secp384r1", "SHA384withECDSA", 120, 104),
	ECDSAP512(8, "secp521r1", "SHA512withECDSA", 158, 139);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String specName;
	/** Name for Signature purposes. Can contain dashes. */
	public final String algName;
    /** Expected size of a DER encoded pubkey in bytes */
	public final int modulusSize;
    /** Maximum (padded) size of a DER-encoded signature (network-format) */
	public final int maxSigSize;
	
	SigType(int bitmask){
		this.bitmask = bitmask;
		this.specName = null;
		this.algName = this.name();
		modulusSize = -1;
		maxSigSize = -1;
	}
	
	SigType(int bitmask, String curve, String alg, int modulus, int maxSize){
		this.bitmask = bitmask;
		specName = curve;
		algName = alg;
		modulusSize = modulus;
		maxSigSize = maxSize;
	}
	
	public Signature get() throws NoSuchAlgorithmException{
		return Signature.getInstance(algName, PreferredAlgorithms.signatureProvider);
	}
	
	public DSASignature get(String sig){
		return new DSASignature(sig);
	}
	
	public DSASignature get(InputStream in) throws IOException{
		return new DSASignature(in);
	}
	
	public DSASignature get(BigInteger r, BigInteger s){
		return new DSASignature(r, s);
	}
	
	public ECGenParameterSpec getSpec(){
		return new ECGenParameterSpec(specName);
	}
}
