/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import net.i2p.util.NativeBigInteger;
import freenet.support.HexUtil;
import freenet.support.Logger;

public class KeyExchange extends KeyAgreementSchemeContext{
	private static final KeyExchType defaultType = PreferredAlgorithms.preferredKeyExchange;
    private static final RandomSource rand = PreferredAlgorithms.random;
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;

    protected final KeyExchType type;	
    
    //ECDH
	private KeyAgreement ka;
	private KeyPair keys;
	
	//DH
	/** My exponent.*/
	private NativeBigInteger myExponent;
	/** My exponential. This is group.g ^ myExponent mod group.p */
	private NativeBigInteger myExponential;
	private DHGroup dhGroup;
	
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
		else{
			try {
				ka = type.get();
				
				keys = KeyUtils.genKeyPair(type.sigType.keyType);

				ka.init(keys.getPrivate());	
			} catch (GeneralSecurityException e) {
				Logger.error(KeyExchange.class, "Internal error; please report:", e);
			}
		}
	}
	
	//DH
	public KeyExchange(DHGroup group, NativeBigInteger myExponent, NativeBigInteger myExponential){
		type = KeyExchType.DH;
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
	
	/**
     * Completes the ECDH exchange: this is CPU intensive
     * @param pubkey
     * @return a SecretKey or null if it fails
     * 
     * **THE OUTPUT SHOULD ALWAYS GO THROUGH A KDF
	 * @throws InvalidKeyException **
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
				Logger.debug(this,
						"My exponential: " + HexUtil.bytesToHex(getPublicKey().getEncoded()));
				Logger.debug(
						this,
						"Peer's exponential: "
								+ HexUtil.bytesToHex(publicKey.getEncoded()));
				Logger.debug(this,
						"SharedSecret = " + HexUtil.bytesToHex(sharedKey));
			}
		}
		
        return sharedKey;
	}
	
	@Deprecated
	public byte[] getHMACKey(ECPublicKey peerExponential) throws InvalidKeyException{
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
	
	public PublicKey getPublicKey() {
        return keys.getPublic();
    }
	
	public static boolean checkExponentialValidity(BigInteger exp){
		return DiffieHellman.checkDHExponentialValidity(KeyExchange.class, exp);
	}
	
	public byte[] getPublicKeyNetworkFormat() {
		if(type.algName == "DH"){
			return DiffieHellmanLightContext.stripBigIntegerToNetworkFormat(myExponential);
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
}
