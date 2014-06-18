package freenet.crypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import net.i2p.util.NativeBigInteger;
import freenet.support.HexUtil;
import freenet.support.Logger;

public class KeyExchange extends KeyAgreementSchemeContext{
	private static final KeyExchType defaultType = PreferredAlgorithms.preferredKeyExchange;
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
	private KeyExchType type;
	private KeyAgreement ka;
	private KeyPair keys;
	
	/** My exponent.*/
	private NativeBigInteger myExponent;
	/** My exponential. This is group.g ^ myExponent mod group.p */
	private NativeBigInteger myExponential;
	private DSAGroup dsaGroup;
	
	
	public KeyExchange(){
		this(defaultType);
	}
	
	public KeyExchange(KeyExchType type){
		this.type = type;
		if(type.name()=="DH"){
			dsaGroup = Global.DSAgroupBigA;
			long time1 = System.currentTimeMillis();
			NativeBigInteger[] params = DiffieHellman.getParams();
			long time2 = System.currentTimeMillis();
			if((time2 - time1) > 300) {
				Logger.error(null, "DiffieHellman.generateLightContext(): time2 is more than 300ms after time1 ("+(time2 - time1)+ ')');
			}
			this.myExponent = params[0];
			this.myExponential = params[1];
		}
		else{
			try {
				ka = type.get();

				KeyPairGenerator kg = KeyPairGenerator.getInstance(
						PreferredAlgorithms.preferredKeyPairGen, 
						PreferredAlgorithms.keyPairProvider);
				kg.initialize(type.getSpec());
				keys = kg.generateKeyPair();

				ka.init(keys.getPrivate());	
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	/**
     * Completes the ECDH exchange: this is CPU intensive
     * @param pubkey
     * @return a SecretKey or null if it fails
     * 
     * **THE OUTPUT SHOULD ALWAYS GO THROUGH A KDF**
     */
	public byte[] getHMACKey(ECPublicKey peerExponential){
		byte[] sharedKey = null;
		synchronized(this) {
            lastUsedTime = System.currentTimeMillis();
		}

		try {
			ka.doPhase(peerExponential, true);
			sharedKey = ka.generateSecret();
		} catch (InvalidKeyException e) {
			Logger.error(this, "InvalidKeyException : "+e.getMessage(),e);
			e.printStackTrace();
		}
		if (logMINOR) {
			Logger.minor(this, "Curve in use: " + type.name().substring(4));
			if(logDEBUG) {
				Logger.debug(this,
						"My exponential: " + HexUtil.bytesToHex(getPublicKey().getEncoded()));
				Logger.debug(
						this,
						"Peer's exponential: "
								+ HexUtil.bytesToHex(peerExponential.getEncoded()));
				Logger.debug(this,
						"SharedSecret = " + HexUtil.bytesToHex(sharedKey));
			}
		}
		
        return sharedKey;
	}
	
	/**
     * Completes the DH exchange: this is CPU intensive
     * @param peerExponential
     * @return a SecretKey or null if it fails
     * 
     */
	public byte[] getHMACKey(NativeBigInteger peerExponential) {
		synchronized(this) {
            lastUsedTime = System.currentTimeMillis();
		}
		
		BigInteger P = dsaGroup.getP();
		NativeBigInteger sharedSecret =
			(NativeBigInteger) peerExponential.modPow(myExponent, P);

		if(logMINOR) {
			Logger.minor(this, "P: "+HexUtil.biToHex(P));
			Logger.minor(this, "My exponent: "+HexUtil.toHexString(myExponent));
			Logger.minor(this, "My exponential: "+HexUtil.toHexString(myExponential));
			Logger.minor(this, "Peer's exponential: "+HexUtil.toHexString(peerExponential));
			Logger.minor(this, "g^ir mod p = " + HexUtil.toHexString(sharedSecret));
		} 
		return sharedSecret.toByteArray();
	}
	
	public ECPublicKey getPublicKey() {
        return (ECPublicKey) keys.getPublic();
    }
	
	public byte[] getPublicKeyNetworkFormat() {
		if(type.algName == "DH"){
			return stripBigIntegerToNetworkFormat(myExponential);
		}
		else{
			byte[] ret = getPublicKey().getEncoded();
			if(ret.length == type.modulusSize) {
				return ret;
			} else if(ret.length > type.modulusSize) {
				throw new IllegalStateException("Encoded public key too long: should be "+type.modulusSize+" bytes but is "+ret.length);
			} else {
				Logger.warning(this, "Padding public key from "+ret.length+" to "+type.modulusSize+" bytes");
				byte[] out = new byte[type.modulusSize];
				System.arraycopy(ret, 0, out, 0, ret.length);
				return ret;
			}
		}
	}
	
	private byte[] stripBigIntegerToNetworkFormat(BigInteger exponential) {
        byte[] data = exponential.toByteArray();
        int targetLength = DiffieHellman.modulusLengthInBytes();
        assert(exponential.signum() == 1);

        if(data.length != targetLength) {
            byte[] newData = new byte[targetLength];
            if((data.length == targetLength+1) && (data[0] == 0)) {
                // Sign bit
                System.arraycopy(data, 1, newData, 0, targetLength);
            } else if(data.length < targetLength) {
                System.arraycopy(data, 0, newData, targetLength-data.length, data.length);
            } else {
                throw new IllegalStateException("Too long!");
            }
            data = newData;
        }
        return data;
    }
}
