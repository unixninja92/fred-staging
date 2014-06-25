/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

public enum KeyExchType {
	DH(1, SigType.DSA),//128
	JFKi(2),
	JFKr(4),
	ECDHP256(8, "ECDH", "secp256r1", 91, 32, SigType.ECDSAP256);
	
	/** Bitmask for aggregation. */
	public final int bitmask;
	public final String specName;
	/** Name for Signature purposes. Can contain dashes. */
	public final String algName;
    /** Expected size of a DER encoded pubkey in bytes */
	public final int modulusSize;
    /** Maximum (padded) size of a DER-encoded signature (network-format) */
	public final int maxSigSize;
	public final SigType sigType;
	
	KeyExchType(int bitmask){
		this.bitmask = bitmask;
		specName = name();
		algName = specName;
		this.modulusSize = -1;
		maxSigSize = -1;
		sigType = null;
	}
	
	KeyExchType(int bitmask, SigType sigType){
		this.bitmask = bitmask;
		specName = name();
		algName = specName;
		this.modulusSize = -1;
		maxSigSize = -1;
		this.sigType = sigType;
	}
	
	KeyExchType(int bitmask, String algName, String specName, int modulusSize, int maxSigSize, SigType sigType){
		this.bitmask = bitmask;
		this.algName = algName;
		this.specName = specName;
		this.modulusSize = modulusSize;
		this.maxSigSize = maxSigSize;
		this.sigType = sigType;
	}
	
	public final KeyAgreement get() throws NoSuchAlgorithmException{
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
	
	public final ECGenParameterSpec getSpec(){
		return new ECGenParameterSpec(specName);
	}
}
