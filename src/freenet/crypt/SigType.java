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

/**
 * Keeps track of properties of different Signature algorithms used in Freenet. 
 * @author unixninja92
 *
 */
public enum SigType{
    @Deprecated
    DSA(1, KeyPairType.DSA),
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

    /**
     * Creates the DSA Enum
     * @param bitmask
     * @param type
     */
    private SigType(int bitmask, KeyPairType type){
        this.bitmask = bitmask;
        this.keyType = type;
        this.algName = this.name();
        modulusSize = -1;
        maxSigSize = -1;
    }

    /**
     * Creates the ECDSA enum values.
     * @param bitmask
     * @param curve The KeyPairType used by the enum value
     * @param alg The name of the alg used (in this case EC)
     * @param modulus Expected size of the public key
     * @param maxSize Max size of the signature 
     */
    private SigType(int bitmask, KeyPairType curve, String alg, int modulus, int maxSize){
        this.bitmask = bitmask;
        keyType = curve;
        algName = alg;
        modulusSize = modulus;
        maxSigSize = maxSize;
    }

    /**
     * Returns an instance of the Signature class using the enum values algorithm. 
     * @return
     */
    public final Signature get(){
        try {
            return Signature.getInstance(algName);
        } catch (NoSuchAlgorithmException e) {
            Logger.error(SigType.class, "Internal error; please report:", e);
        }
        return null;
    }

    /**
     * Wraps the given sig in a DSASignature class. 
     * @param sig The sig to be wrapped as a string
     * @return The Sig as a DSASignature
     */
    public final DSASignature get(String sig){
        if(this != DSA){
            throw new UnsupportedTypeException(this);
        }
        return new DSASignature(sig);
    }

    /**
     * Wraps the given sig in a DSASignature class. 
     * @param sig The sig to be wrapped as an InputStream
     * @return The Sig as a DSASignature
     */
    public final DSASignature get(InputStream in) throws IOException{
        if(this != DSA){
            throw new UnsupportedTypeException(this);
        }
        return new DSASignature(in);
    }
    /**
     * Wraps the given sig in a DSASignature class. 
     * @param sig The sig as it's BigInteger r and s components 
     * @return The Sig as a DSASignature
     */
    public final DSASignature get(BigInteger r, BigInteger s){
        if(this != DSA){
            throw new UnsupportedTypeException(this);
        }
        return new DSASignature(r, s);
    }

}
