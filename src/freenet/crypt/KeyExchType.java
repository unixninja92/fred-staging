/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import freenet.support.Logger;

public enum KeyExchType {
	@Deprecated
	DH(1, SigType.DSA),//128
	ECDHP256(2, "ECDH", "secp256r1", 91, 32, SigType.ECDSAP256);
	
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
	
	public final KeyAgreement get()throws UnsupportedTypeException{
		if(this == DH){
			throw new UnsupportedTypeException(this);
		}
		//FIXME switch to preferred provider
		try {
			return KeyAgreement.getInstance(algName, PreferredAlgorithms.BC);
		} catch (NoSuchAlgorithmException e) {
			Logger.error(KeyExchType.class, "Internal error; please report:", e);
		}
		return null;
	}
	
	public final ECGenParameterSpec getSpec()throws UnsupportedTypeException{
		if(this == DH){
			throw new UnsupportedTypeException(this);
		}
		return new ECGenParameterSpec(specName);
	}
}
