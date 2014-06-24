/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

import net.i2p.util.NativeBigInteger;
import freenet.io.comm.Peer;
import freenet.node.NodeCrypto;
import freenet.node.PeerNode;
import freenet.support.HexUtil;
import freenet.support.Logger;

public class KeyExchange extends KeyAgreementSchemeContext{
	private static final KeyExchType defaultType = PreferredAlgorithms.preferredKeyExchange;
    private static final RandomSource rand = PreferredAlgorithms.random;
	private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
	
    //ECDH
    private final KeyExchType type;
	private KeyAgreement ka;
	private KeyPair keys;
	
	
	//DH
	/** My exponent.*/
	private NativeBigInteger myExponent;
	/** My exponential. This is group.g ^ myExponent mod group.p */
	private NativeBigInteger myExponential;
	private DHGroup dhGroup;
	
	//JFK
	private byte[] nonceI; //Initiators nonce 
	private byte[] nonceR; //Responders nonce
	private byte[] hashnI; //N'i
	private byte[] hashnR; //N'r
	private byte[] exponentialI; //Initiators exponential
	private byte[] exponentialR;//Responders exponential
	private PeerNode peer;
	private int modulusLength;
	private KeyExchange underlyingExch; //IDi and IDr
	
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
		else if(type.name() == "JFKi" || type.name() == "JFKr"){
			//throw an error
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
	
	//JFK
	public KeyExchange(KeyExchType underlying, int nonceSize, PeerNode pn){
		type = KeyExchType.JFKi;
		this.underlyingExch = new KeyExchange(underlying);
		this.modulusLength = underlyingExch.type.modulusSize;
		this.peer = pn;
		
		nonceI = new byte[nonceSize];
		rand.nextBytes(nonceI);
		
		Hash hash = new Hash();
		hashnI = hash.getHash(nonceI);

		exponentialI = underlyingExch.getPublicKeyNetworkFormat();
	}
	
	public KeyExchange(KeyExchType underlying, int nonceSize, byte[] nonceI, byte[] exponentialI, PeerNode peerNode){
		type = KeyExchType.JFKr;
		this.underlyingExch = new KeyExchange(underlying);
		this.modulusLength = underlyingExch.type.modulusSize;
		this.peer = peerNode;
		this.nonceI = nonceI;
		this.exponentialI = exponentialI;
		if(!DiffieHellman.checkDHExponentialValidity(this.getClass(), 
				new NativeBigInteger(1,exponentialI))){
			Logger.error(this, "We can't accept the exponential "+peerNode+" sent us!! REDFLAG: IT CAN'T HAPPEN UNLESS AGAINST AN ACTIVE ATTACKER!!");
		}
		
		this.nonceR = new byte[nonceSize];
		rand.nextBytes(nonceR);
		
		Hash hash = new Hash();
		hashnR = hash.getHash(nonceR);
		
		exponentialR = underlyingExch.getPublicKeyNetworkFormat();
		//TODO set sig
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
	
	//sent by initiator
	public final byte[] genMessage1(boolean hash, boolean unknownInitiator){
		if(type==KeyExchType.JFKi){
			int offset = 0;
			int nonceSize = hash ? hashnI.length: nonceI.length;
			byte[] message1 = new byte[nonceSize+modulusLength
			                           +(unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)];
			System.arraycopy((hash ? hashnI : nonceI), 0, message1, offset, nonceSize);
			offset += nonceSize;
			System.arraycopy(exponentialI, 0, message1, offset, modulusLength);
			return message1;
		}
		return null;
	}
	
	//sent by reciver
	public final byte[] genMessage2(byte[] transientKey, byte[] replyToAddress, byte[] sig){
		if(type==KeyExchType.JFKr){
			byte[] message2 = new byte[nonceI.length + nonceR.length+modulusLength+
			                           sig.length + hashnR.length];

			int offset = 0;
			System.arraycopy(nonceI, 0, message2, offset, nonceI.length);
			offset += nonceI.length;
			System.arraycopy(nonceR, 0, message2, offset, nonceR.length);
			offset += nonceR.length;
			System.arraycopy(exponentialR, 0, message2, offset, modulusLength);
			offset += modulusLength;

			System.arraycopy(sig, 0, message2, offset, sig.length);
			offset += sig.length;

			MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, transientKey);

			byte[] authenticator = mac.getMAC(assembleJFKAuthenticator(exponentialR, exponentialI, nonceR, nonceI, replyToAddress));

			System.arraycopy(authenticator, 0, message2, offset, hashnR.length);

			return message2;
		}
		return null;
	}
	
	//done by initiator
	public void processMessage2(byte[] nonceR, byte[] exponentialR, byte[] publicKeyR, byte[] locallyExpectedExponentials, byte[] sigR, byte[] authenticator){
		this.nonceR = nonceR;
		this.exponentialR = exponentialR;
		

		try {
			CryptSignature sig;
			if(underlyingExch.type == KeyExchType.DH){
				if(!DiffieHellman.checkDHExponentialValidity(this.getClass(), 
						new NativeBigInteger(1,exponentialR))){
					Logger.error(this, "We can't accept the exponential "+peer.getPeer()+" sent us!! REDFLAG: IT CAN'T HAPPEN UNLESS AGAINST AN ACTIVE ATTACKER!!");
				}
				sig = new CryptSignature(SigType.DSA, publicKeyR);
				if(!sig.verify(sigR, locallyExpectedExponentials)){
					Logger.error(this, "The signature verification has failed in JFK(2)!! "+peer.getPeer());
					return;
				}
			} else{
				sig = new CryptSignature(PreferredAlgorithms.preferredSignature, publicKeyR);
				if(!sig.verify(sigR, locallyExpectedExponentials)){
			    	  Logger.error(this, "The ECDSA signature verification has failed in JFK(2)!! "+peer.getPeer());
		              if(logDEBUG) Logger.debug(this, "Expected signature on "+HexUtil.bytesToHex(exponentialR)+
		            		  " with "+HexUtil.bytesToHex(publicKeyR)+
		            		  " signature "+HexUtil.bytesToHex(sigR));
		              return;
				}
			}
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CryptFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	/*
	 * Assemble what will be the jfk-Authenticator :
	 * computed over the Responder exponentials and the Nonces and
	 * used by the responder to verify that the round-trip has been done
	 *
	 */
	private byte[] assembleJFKAuthenticator(byte[] gR, byte[] gI, byte[] nR, byte[] nI, byte[] address) {
		byte[] authData=new byte[gR.length + gI.length + nR.length + nI.length + address.length];
		int offset = 0;

		System.arraycopy(gR, 0, authData, offset ,gR.length);
		offset += gR.length;
		System.arraycopy(gI, 0, authData, offset, gI.length);
		offset += gI.length;
		System.arraycopy(nR, 0,authData, offset, nR.length);
		offset += nR.length;
		System.arraycopy(nI, 0,authData, offset, nI.length);
		offset += nI.length;
		System.arraycopy(address, 0, authData, offset, address.length);

		return authData;
	}
	
	/**
	 * 
	 * @param exponential: computedExponential
	 * @param nI: nonceInitiatorHashed
	 * @param nR: nonceResponder
	 * @param what: what kind of key
	 * @return
	 */
	public static final byte[] computeJFKSharedKey(byte[] exponential, byte[] nI, byte[] nR, String what) {
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
		MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, exponential);
		return mac.getMAC(toHash);
	}
	
	public ECPublicKey getPublicKey() {
        return (ECPublicKey) keys.getPublic();
    }
	
	public boolean checkExponentialValidity(BigInteger exp){
		return DiffieHellman.checkDHExponentialValidity(getClass(), exp);
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
