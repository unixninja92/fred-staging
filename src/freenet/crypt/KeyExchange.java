package freenet.crypt;

import java.io.UnsupportedEncodingException;
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
	
    //ECDH
    private KeyExchType type;
	private KeyAgreement ka;
	private KeyPair keys;
	
	
	//DH
	/** My exponent.*/
	private NativeBigInteger myExponent;
	/** My exponential. This is group.g ^ myExponent mod group.p */
	private NativeBigInteger myExponential;
	private DHGroup dhGroup;
	
	//JFK
//	private byte[] nI; //Initiators nonce 
//	private byte[] nR; //Responders nonce
//	private byte[] hashnI; //N'i
//	private byte[] myxponential; //Initiators exponential
//	private byte[] theirExponential;//Responders exponential
//	private KeyExchange underlyingExch; //IDi
	
	public KeyExchange(){
		this(defaultType);
	}
	
	public KeyExchange(KeyExchType type){
		this.type = type;
		if(type.name()=="DH"){
			dhGroup = Global.DHgroupA;
			long time1 = System.currentTimeMillis();
			NativeBigInteger[] params = DiffieHellman.getParams();
			long time2 = System.currentTimeMillis();
			if((time2 - time1) > 300) {
				Logger.error(null, "DiffieHellman.generateLightContext(): time2 is more than 300ms after time1 ("+(time2 - time1)+ ')');
			}
			this.myExponent = params[0];
			this.myExponential = params[1];
		}
		else if(type.name() == "JFK"){
			
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
	
	public KeyExchange(DHGroup group, NativeBigInteger myExponent, NativeBigInteger myExponential){
		dhGroup = group;
		this.myExponent = myExponent;
		checkExponentialValidity(myExponential);
		this.myExponential = myExponential;
	}
	
	public KeyExchange(DHGroup group, NativeBigInteger myExponent){
		this(group, myExponent, (NativeBigInteger) group.getG().modPow(myExponent, group.getP()));
	}
	
	public KeyExchange(NativeBigInteger myExponent, NativeBigInteger myExponential){
		this(Global.DHgroupA, myExponent, myExponential);
	}
	
	public KeyExchange(NativeBigInteger myExponent){
		this(Global.DHgroupA, myExponent);
	}
	
	public KeyExchange(DHGroup group){
		this(KeyExchType.DH);
		dhGroup = group;
	}
	/**
     * Completes the ECDH exchange: this is CPU intensive
     * @param pubkey
     * @return a SecretKey or null if it fails
     * 
     * **THE OUTPUT SHOULD ALWAYS GO THROUGH A KDF**
     */
	public byte[] getSharedSecrect(ECPublicKey peerExponential){
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
	
	@Deprecated
	public byte[] getHMACKey(ECPublicKey peerExponential){
		return getSharedSecrect(peerExponential);
	}
	
	/**
     * Completes the DH exchange: this is CPU intensive
     * @param peerExponential
     * @return a SecretKey or null if it fails
     * 
     */
	public byte[] getSharedSecrect(NativeBigInteger peerExponential) {
		synchronized(this) {
            lastUsedTime = System.currentTimeMillis();
		}
		
		BigInteger P = dhGroup.getP();
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
	
	@Deprecated
	public byte[] getHMACKey(NativeBigInteger peerExponential){
		return getSharedSecrect(peerExponential);
	}
	
	/**
	 * 
	 * @param exponential: computedExponential
	 * @param nI: nonceInitiatorHashed
	 * @param nR: nonceResponder
	 * @param what: what kind of key
	 * @return
	 */
	public static byte[] computeJFKSharedKey(byte[] exponential, byte[] nI, byte[] nR, String what) {
		assert("0".equals(what) || "1".equals(what) || "2".equals(what) || "3".equals(what)
				|| "4".equals(what) || "5".equals(what) || "6".equals(what) || "7".equals(what));
		byte[] number = null;
		try {
			number = what.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		byte[] toHash = new byte[nI.length + nR.length + number.length];
		int offset = 0;
		System.arraycopy(nI, 0, toHash, offset, nI.length);
		offset += nI.length;
		System.arraycopy(nR, 0, toHash, offset, nR.length);
		offset += nR.length;
		System.arraycopy(number, 0, toHash, offset, number.length);
		return HMAC.macWithSHA256(exponential, toHash, HashType.SHA256.hashLength);
	}
	
	public ECPublicKey getPublicKey() {
        return (ECPublicKey) keys.getPublic();
    }
	
	public boolean checkExponentialValidity(BigInteger exp){
		return DiffieHellman.checkDHExponentialValidity(getClass(), exp);
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
