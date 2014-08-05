/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import freenet.support.HexUtil;
import freenet.support.Logger;

public class KeyExchange extends KeyAgreementSchemeContext{
    public static final KeyExchType preferredKeyExchange = KeyExchType.ECDHP256;
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;

    protected final KeyExchType type;	

    //ECDH
    private KeyAgreement ka;
    private KeyPair keys;

    public KeyExchange(KeyExchType type){
        this.type = type;
        try {
            keys = KeyGenUtils.genKeyPair(type.sigType.keyType);

            ka = type.get();
            ka.init(keys.getPrivate());	
        } catch (GeneralSecurityException e) {
            Logger.error(KeyExchange.class, "Internal error; please report:", e);
        } catch (UnsupportedTypeException e) {
            Logger.error(KeyExchange.class, "Internal error; please report:", e);
        }
    }


    /**
     * Completes the ECDH exchange: this is CPU intensive
     * @param pubkey
     * @return a SecretKey or null if it fails
     * 
     * **THE OUTPUT SHOULD ALWAYS GO THROUGH A KDF
     * @throws InvalidKeyException 
     * @throws UnsupportedTypeException **
     */
    public byte[] getSharedSecrect(PublicKey publicKey) throws InvalidKeyException{
        byte[] sharedKey = null;
        synchronized(this) {
            lastUsedTime = System.currentTimeMillis();
        }
        ka.doPhase(publicKey, true);
        sharedKey = ka.generateSecret();

        if (logMINOR) {
            Logger.minor(this, "Curve in use: " + type.name().substring(4));
            if(logDEBUG) {
                Logger.debug(this, "My exponential: " + 
                        HexUtil.bytesToHex(getPublicKey().getEncoded()));
                Logger.debug(this, "Peer's exponential: " + 
                        HexUtil.bytesToHex(publicKey.getEncoded()));
                Logger.debug(this, "SharedSecret = " + 
                        HexUtil.bytesToHex(sharedKey));
            }
        }

        return sharedKey;
    }

    @Deprecated
    public byte[] getHMACKey(ECPublicKey peerExponential) throws InvalidKeyException{
        return getSharedSecrect(peerExponential);
    }

    public PublicKey getPublicKey() {
        return keys.getPublic();
    }

    public byte[] getPublicKeyNetworkFormat() {
        byte[] ret = getPublicKey().getEncoded();
        if(ret.length == type.modulusSize) {
            return ret;
        } else if(ret.length > type.modulusSize) {
            throw new IllegalStateException("Encoded public key too long: should be "+
                    type.modulusSize+" bytes but is "+ret.length);
        } else {
            Logger.warning(this, "Padding public key from "+ret.length+" to "+type.modulusSize+" bytes");
            byte[] out = new byte[type.modulusSize];
            System.arraycopy(ret, 0, out, 0, ret.length);
            return ret;
        }
    }
}