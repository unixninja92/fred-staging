/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import freenet.support.Logger;

/**
 * 
 * @author unixninja92
 *
 */
public enum KeyExchType {
    ECDHP256(2, "ECDH", "secp256r1", 91, 32, SigType.ECDSAP256),
    ECDHP384(2, "ECDH", "secp384r1", 120, 48, SigType.ECDSAP384),
    ECDHP521(2, "ECDH", "secp521r1", 158, 66, SigType.ECDSAP512);

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

    /**
     * Creates an ECDH enum value with a specified curve. 
     * @param bitmask
     * @param algName The name of the alg being used
     * @param specName Java's name for the curve being used
     * @param modulusSize The key size
     * @param maxSigSize The maximum sig size
     * @param sigType They type of sig that will be used (matches alg)
     */
    private KeyExchType(int bitmask, String algName, String specName, int modulusSize, 
            int maxSigSize, SigType sigType){
        this.bitmask = bitmask;
        this.algName = algName;
        this.specName = specName;
        this.modulusSize = modulusSize;
        this.maxSigSize = maxSigSize;
        this.sigType = sigType;
    }

    /**
     * Returns an instance of KeyAgreement using the alg and curve of the enum value. 
     */
    public final KeyAgreement get() {
        try {
            return KeyAgreement.getInstance(algName);
        } catch (NoSuchAlgorithmException e) {
            Logger.error(KeyExchType.class, "Internal error; please report:", e);
        }
        return null;
    }

    /**
     * Generates the ECGenParameterSpec for the curve. 
     * @return Returns the generated ECGenParameterSpec
     */
    public final ECGenParameterSpec getSpec() {
        return new ECGenParameterSpec(specName);
    }
}
