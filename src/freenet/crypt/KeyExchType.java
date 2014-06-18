package freenet.crypt;

import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

public enum KeyExchType {
	DH(1, 128),
	ECDHP256(2, "ECDH", "secp256r1", 91, 32);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String specName;
	/** Name for Signature purposes. Can contain dashes. */
	public final String algName;
    /** Expected size of a DER encoded pubkey in bytes */
	public final int modulusSize;
    /** Maximum (padded) size of a DER-encoded signature (network-format) */
	public final int maxSigSize;
	
	KeyExchType(int bitmask, int modulusSize){
		this.bitmask = bitmask;
		specName = name();
		algName = specName;
		this.modulusSize = modulusSize;
		maxSigSize = -1;
	}
	
	KeyExchType(int bitmask, String algName, String specName, int modulusSize, int maxSigSize){
		this.bitmask = bitmask;
		this.algName = algName;
		this.specName = specName;
		this.modulusSize = modulusSize;
		this.maxSigSize = maxSigSize;
	}
	
	public KeyAgreement get() throws NoSuchAlgorithmException{
		//FIXME switch to preferred provider
		return KeyAgreement.getInstance(algName, PreferredAlgorithms.BC);
	}
	
//	public KeyAgreementSchemeContext getSchemeContext(){
//		if(name() == "DH"){
//			return new DiffieHellmanLightContext();
//		}
//		else{
//			return new ECDHLightContext();
//		}
//	}
	
	public ECGenParameterSpec getSpec(){
		return new ECGenParameterSpec(specName);
	}
}
