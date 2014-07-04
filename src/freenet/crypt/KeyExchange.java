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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import org.bouncycastle.util.Arrays;

import net.i2p.util.NativeBigInteger;
import freenet.node.NodeCrypto;
import freenet.node.PeerNode;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucketFactory;

public class KeyExchange extends KeyAgreementSchemeContext{
	private static final KeyExchType defaultType = PreferredAlgorithms.preferredKeyExchange;
    private static final RandomSource rand = PreferredAlgorithms.random;
	private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;

    private KeyExchType type;	
    
    //ECDH
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
	
	public byte[] outgoingKey;
	public byte[] incommingKey;
	public byte[] jfkKe;
	public byte[] jfkKa;
	public byte[] hmacKey;
	public byte[] ivKey;
	public byte[] ivNonce;
	public int ourInitialSeqNum;
	public int theirInitialSeqNum;
	public int ourInitialMsgID;
	public int theirInitialMsgID;
	
	/** The following is used in the HMAC calculation of JFK message3 and message4 */
	private static final byte[] JFK_PREFIX_INITIATOR, JFK_PREFIX_RESPONDER;
	static {
		byte[] I = null,R = null;
		try {
			I = "I".getBytes("UTF-8");
			R = "R".getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		JFK_PREFIX_INITIATOR = I;
		JFK_PREFIX_RESPONDER = R;
	}
	
	
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
				
				keys = KeyUtils.genKeyPair(type.sigType.keyType);

				ka.init(keys.getPrivate());	
			} catch (NoSuchAlgorithmException e) {
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
	
	//process message 1
	public KeyExchange(KeyExchType underlying, PeerNode peerNode, int nonceSize, byte[] nonceI, byte[] exponentialI){
		this(underlying, nonceSize, peerNode);
		type = KeyExchType.JFKr;
		this.processMessage1(nonceSize, nonceI, exponentialI);
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
	public byte[] getSharedSecrect(PublicKey publicKey){
		byte[] sharedKey = null;
		synchronized(this) {
            lastUsedTime = System.currentTimeMillis();
		}

		try {
			ka.doPhase(publicKey, true);
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
								+ HexUtil.bytesToHex(publicKey.getEncoded()));
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
	
	public byte[] getSharedSecrect(byte[] peerExponential){
		if(underlyingExch.type == KeyExchType.DH){
			return getSharedSecrect(new NativeBigInteger(1, peerExponential));
		}
		else{
			return getSharedSecrect(KeyUtils.getPublicKey(peerExponential));
		}
	}
	
	@Deprecated
	public byte[] getHMACKey(NativeBigInteger peerExponential){
		return getSharedSecrect(peerExponential);
	}
	
	/**
	 * 
	 * @param exponential: computedExponential
	 * @param n'I: nonceInitiatorHashed
	 * @param nR: nonceResponder
	 * @param what: what kind of key
	 * @return
	 */
	public final byte[] getSharedSecrect(byte[] exponential, String what) {
		assert("0".equals(what) || "1".equals(what) || "2".equals(what) || "3".equals(what)
				|| "4".equals(what) || "5".equals(what) || "6".equals(what) || "7".equals(what));
		byte[] number = null;
		try {
			number = what.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		byte[] toHash = new byte[hashnI.length + nonceR.length + number.length];
		int offset = 0;
		System.arraycopy(hashnI, 0, toHash, offset, hashnI.length);
		offset += hashnI.length;
		System.arraycopy(nonceR, 0, toHash, offset, nonceR.length);
		offset += nonceR.length;
		System.arraycopy(number, 0, toHash, offset, number.length);
		MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, exponential);
		return mac.getMAC(toHash);
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
	
	//for receiver
	public final void processMessage1(int nonceSize, byte[] nonceI, byte[] exponentialI){
		this.nonceI = nonceI;
		this.exponentialI = exponentialI;
		if(!DiffieHellman.checkDHExponentialValidity(this.getClass(), 
				new NativeBigInteger(1,exponentialI))){
			Logger.error(this, "We can't accept the exponential "+peer.getPeer()+" sent us!! REDFLAG: IT CAN'T HAPPEN UNLESS AGAINST AN ACTIVE ATTACKER!!");
		}
		
		this.nonceR = new byte[nonceSize];
		rand.nextBytes(nonceR);
		
		Hash hash = new Hash();
		hashnR = hash.getHash(nonceR);
		
		exponentialR = underlyingExch.getPublicKeyNetworkFormat();
	}
	
	//sent by receiver
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

			byte[] authenticator = mac.getMAC(assembleJFKAuthenticator(replyToAddress));

			System.arraycopy(authenticator, 0, message2, offset, hashnR.length);

			return message2;
		}
		return null;
	}
	
	//done by initiator
	public void processMessage2(byte[] nonceR, byte[] exponentialR, byte[] publicKeyR, byte[] locallyExpectedExponentials, byte[] sigR){
		this.nonceR = nonceR;
		this.exponentialR = exponentialR;
		
		try {
			CryptSignature sig;
			if(underlyingExch.type == KeyExchType.DH){
				if(!DiffieHellman.checkDHExponentialValidity(this.getClass(), 
						new NativeBigInteger(1,exponentialR))){
					Logger.error(this, "We can't accept the exponential "+peer.getPeer()+" sent us!! REDFLAG: IT CAN'T HAPPEN UNLESS AGAINST AN ACTIVE ATTACKER!!");
				}
			}
			sig = new CryptSignature(underlyingExch.type.sigType, publicKeyR);
			if(!sig.verify(sigR, locallyExpectedExponentials)){
				Logger.error(this, "The signature verification has failed in JFK(2)!! "+peer.getPeer());
				if(logDEBUG) Logger.debug(this, "Expected signature on "+HexUtil.bytesToHex(exponentialR)+
						" with "+HexUtil.bytesToHex(publicKeyR)+
						" signature "+HexUtil.bytesToHex(sigR));
				return;
			}
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CryptFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//send by initiator 
	public byte[] genMessage3(byte[] sig, long trackerID, long bootID, byte[] ref, byte[] authenticator){
		int blockSize = CryptBitSetType.RijndaelPCFB.blockSize;
		int ivSize = blockSize >> 3;
		
		byte[] data = new byte[8 + 8 + ref.length];
		int ptr = 0;
		System.arraycopy(Fields.longToBytes(trackerID), 0, data, ptr, 8);
		ptr += 8;
		if(logMINOR) Logger.minor(this, "Sending tracker ID "+trackerID+" in JFK(3)");
		System.arraycopy(Fields.longToBytes(bootID), 0, data, ptr, 8);
		ptr += 8;
		System.arraycopy(ref, 0, data, ptr, ref.length);
		final byte[] message3 = new byte[nonceI.length*2 + // nI, nR
				                           modulusLength*2 + // g^i, g^r
				                           hashnI.length + // authenticator
				                           hashnI.length + // HMAC(cyphertext)
				                           ivSize + // IV
				                           sig.length + // Signature
				                           data.length]; // The bootid+noderef'
		
		int offset = 0;
		// Ni
		System.arraycopy(nonceI, 0, message3, offset, nonceI.length);
		offset += nonceI.length;
		if(logDEBUG) Logger.debug(this, "We are sending Ni : " + HexUtil.bytesToHex(nonceI));
		// Nr
		System.arraycopy(nonceR, 0, message3, offset, nonceR.length);
		offset += nonceR.length;
		// g^i
		System.arraycopy(exponentialI, 0,message3, offset, exponentialI.length);
		offset += exponentialI.length;
		// g^r
		System.arraycopy(exponentialR, 0,message3, offset, exponentialR.length);
		offset += exponentialR.length;

		// Authenticator
		System.arraycopy(authenticator, 0, message3, offset, authenticator.length);
		offset += authenticator.length;
		
		byte[] computedExponential = underlyingExch.getSharedSecrect(exponentialR);
		
		
		outgoingKey = getSharedSecrect(computedExponential, "0");
		incommingKey = getSharedSecrect(computedExponential, "7");
		jfkKe = getSharedSecrect(computedExponential, "1");
		jfkKa = getSharedSecrect(computedExponential, "2");

		hmacKey = getSharedSecrect(computedExponential, "3");
		ivKey = getSharedSecrect(computedExponential, "4");
		ivNonce = getSharedSecrect(computedExponential, "5");
		
		byte[] sharedData = getSharedSecrect(computedExponential, "6");
	    Arrays.fill(computedExponential, (byte)0);
	    ourInitialSeqNum = ((sharedData[0] & 0xFF) << 24)
	    		| ((sharedData[1] & 0xFF) << 16)
	    		| ((sharedData[2] & 0xFF) << 8)
	    		| (sharedData[3] & 0xFF);
	    theirInitialSeqNum = ((sharedData[4] & 0xFF) << 24)
	    		| ((sharedData[5] & 0xFF) << 16)
	    		| ((sharedData[6] & 0xFF) << 8)
	    		| (sharedData[7] & 0xFF);

	    ourInitialMsgID = ((sharedData[8] & 0xFF) << 24)
	    		| ((sharedData[9] & 0xFF) << 16)
	    		| ((sharedData[10] & 0xFF) << 8)
	    		| (sharedData[11] & 0xFF);
	    theirInitialMsgID = ((sharedData[12] & 0xFF) << 24)
	    		| ((sharedData[13] & 0xFF) << 16)
	    		| ((sharedData[14] & 0xFF) << 8)
	    		| (sharedData[15] & 0xFF);
		
		byte[] iv = new byte[ivSize];
		PreferredAlgorithms.random.nextBytes(iv);
		
		int cleartextOffset = 0;
		byte[] cleartext = new byte[JFK_PREFIX_INITIATOR.length + ivSize + sig.length + data.length];
		System.arraycopy(JFK_PREFIX_INITIATOR, 0, cleartext, cleartextOffset, JFK_PREFIX_INITIATOR.length);
		cleartextOffset += JFK_PREFIX_INITIATOR.length;
		System.arraycopy(iv, 0, cleartext, cleartextOffset, ivSize);
		cleartextOffset += ivSize;
		System.arraycopy(sig, 0, cleartext, cleartextOffset, sig.length);
		cleartextOffset += sig.length;
		System.arraycopy(data, 0, cleartext, cleartextOffset, data.length);
		cleartextOffset += data.length;

		int cleartextToEncypherOffset = JFK_PREFIX_INITIATOR.length + ivSize;
		
		CryptBitSet cryptBits = new CryptBitSet(CryptBitSetType.RijndaelPCFB, jfkKe, iv);
		byte[] ciphertext = cryptBits.encrypt(cleartext, cleartextToEncypherOffset, cleartext.length-cleartextToEncypherOffset);
		
		// We compute the HMAC of (prefix + cyphertext) Includes the IV!
		MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, jfkKa);
		byte[] hmac = mac.getMAC(ciphertext);

		// copy stuffs back to the message
		System.arraycopy(hmac, 0, message3, offset, hmac.length);
		offset += hmac.length;
		System.arraycopy(iv, 0, message3, offset, ivSize);
		offset += ivSize;
		System.arraycopy(ciphertext, cleartextToEncypherOffset, message3, offset, ciphertext.length-cleartextToEncypherOffset);

		return message3;
	}
	
	//Processed by reciver
	public byte[] processMessage3(byte[] hmac, byte[] cypheredPayload, int decypheredPayloadOffset, byte[] identity, byte[] publicKeyI){
		int blockSize = CryptBitSetType.RijndaelPCFB.blockSize;
		int ivSize = blockSize >> 3;
	    		
		byte[] computedExponential = underlyingExch.getSharedSecrect(exponentialI);
		
		outgoingKey = getSharedSecrect(computedExponential, "0");
		incommingKey = getSharedSecrect(computedExponential, "7");
		jfkKe = getSharedSecrect(computedExponential, "1");
		jfkKa = getSharedSecrect(computedExponential, "2");

		hmacKey = getSharedSecrect(computedExponential, "3");
		ivKey = getSharedSecrect(computedExponential, "4");
		ivNonce = getSharedSecrect(computedExponential, "5");
		
		/* Bytes  1-4:  Initial sequence number for the initiator
		 * Bytes  5-8:  Initial sequence number for the responder
		 * Bytes  9-12: Initial message id for the initiator
		 * Bytes 13-16: Initial message id for the responder
		 * Note that we are the responder */
		byte[] sharedData = getSharedSecrect(computedExponential, "6");
		Arrays.fill(computedExponential, (byte)0);
		theirInitialSeqNum = ((sharedData[0] & 0xFF) << 24)
				| ((sharedData[1] & 0xFF) << 16)
				| ((sharedData[2] & 0xFF) << 8)
				| (sharedData[3] & 0xFF);
		ourInitialSeqNum = ((sharedData[4] & 0xFF) << 24)
				| ((sharedData[5] & 0xFF) << 16)
				| ((sharedData[6] & 0xFF) << 8)
				| (sharedData[7] & 0xFF);
		theirInitialMsgID= ((sharedData[8] & 0xFF) << 24)
				| ((sharedData[9] & 0xFF) << 16)
				| ((sharedData[10] & 0xFF) << 8)
				| (sharedData[11] & 0xFF);
		ourInitialMsgID= ((sharedData[12] & 0xFF) << 24)
				| ((sharedData[13] & 0xFF) << 16)
				| ((sharedData[14] & 0xFF) << 8)
				| (sharedData[15] & 0xFF);
		
		int ivLength = ivSize;
		// We compute the HMAC of ("I"+cyphertext) : the cyphertext includes the IV!
		MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, jfkKa);
		if(!mac.verifyData(hmac, cypheredPayload)) {
			Logger.error(this, "The inner-HMAC doesn't match; let's discard the packet JFK(3) - "+peer);
			return null;
		}
		
		byte[] iv = new byte[ivSize];
		System.arraycopy(cypheredPayload, decypheredPayloadOffset, iv, 0, ivLength);
		decypheredPayloadOffset += ivLength;
		
		CryptBitSet cryptBits = new CryptBitSet(CryptBitSetType.RijndaelPCFB, jfkKe, iv);
		byte[] cleartext = cryptBits.decrypt(cypheredPayload, decypheredPayloadOffset, cypheredPayload.length-decypheredPayloadOffset);
	    
	    
	    int sigLength;
	    if(underlyingExch.type == KeyExchType.DH){
	    	sigLength = this.dsaSig.length;
	    }
	    else{
	    	sigLength = this.ecdsaSig.length;
	    }
		byte[] sigI = new byte[sigLength];
		System.arraycopy(cleartext, decypheredPayloadOffset, sigI, 0, sigLength);
		decypheredPayloadOffset += sigLength;
		byte[] data = new byte[cleartext.length - decypheredPayloadOffset];
		System.arraycopy(cleartext, decypheredPayloadOffset, data, 0, cleartext.length - decypheredPayloadOffset);
		
		byte[] toVerify = assembleDHParams(identity, data);
		
		try {
			CryptSignature sig = new CryptSignature(underlyingExch.type.sigType, publicKeyI);
			if(!sig.verify(sigI, toVerify)){
				Logger.error(this, "The signature verification has failed!! JFK(3) - "+peer.getPeer());
				return null;
			}
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CryptFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return data;
	}
	
	//sent by reciver
	public byte[] genMessage4(byte[] identity, byte[] data, byte[] refI, byte[] sig, CryptBitSet cryptBits, byte[] newTrackerID, boolean sameAsOldTrackerID, byte[] outgoingBootID, long bootID, SigType sigType){
		byte[] iv = cryptBits.genIV();
		int ivLength = iv.length;
		
		int dataLength = data.length - refI.length;
		
		byte[] cyphertext = new byte[JFK_PREFIX_RESPONDER.length + ivLength + sig.length + dataLength];
		int cleartextOffset = 0;
		System.arraycopy(JFK_PREFIX_RESPONDER, 0, cyphertext, cleartextOffset, JFK_PREFIX_RESPONDER.length);
		cleartextOffset += JFK_PREFIX_RESPONDER.length;
		System.arraycopy(iv, 0, cyphertext, cleartextOffset, ivLength);
		cleartextOffset += ivLength;
		System.arraycopy(sig, 0, cyphertext, cleartextOffset, sig.length);
		cleartextOffset += sig.length;
		System.arraycopy(data, 0, cyphertext, cleartextOffset, dataLength);
		cleartextOffset += dataLength;
		// Now encrypt the cleartext[Signature]
		int cleartextToEncypherOffset = JFK_PREFIX_RESPONDER.length + ivLength;
		
		//set iv
		byte[] cleartext = cryptBits.decrypt(cyphertext, cleartextToEncypherOffset, cyphertext.length - cleartextToEncypherOffset);
	    
		
		// We compute the HMAC of (prefix + iv + signature)
		MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, jfkKa);
		byte[] hmac = mac.getMAC(cyphertext);
		
		byte[] message4 = new byte[hashnI.length + ivLength + (cyphertext.length - cleartextToEncypherOffset)];
		
		return message4;
	}
	
	
	/*
	 * Assemble what will be the jfk-Authenticator :
	 * computed over the Responder exponentials and the Nonces and
	 * used by the responder to verify that the round-trip has been done
	 *
	 */
	private byte[] assembleJFKAuthenticator(byte[] address) {
		byte[] authData=new byte[exponentialR.length + exponentialI.length + 
		                         nonceR.length + nonceI.length + address.length];
		int offset = 0;

		System.arraycopy(exponentialR, 0, authData, offset ,exponentialR.length);
		offset += exponentialR.length;
		System.arraycopy(exponentialI, 0, authData, offset, exponentialI.length);
		offset += exponentialI.length;
		System.arraycopy(nonceR, 0,authData, offset, nonceR.length);
		offset += nonceR.length;
		System.arraycopy(nonceI, 0,authData, offset, nonceI.length);
		offset += nonceI.length;
		System.arraycopy(address, 0, authData, offset, address.length);

		return authData;
	}
	
	/*
	 * Prepare DH parameters of message2 for them to be signed (useful in message3 to check the sig)
	 */
//	private byte[] assembleDHParams(byte[] exponential, DSAGroup group) {
//		byte[] _myGroup = group.getP().toByteArray();
//		byte[] toSign = new byte[exponential.length + _myGroup.length];
//
//		System.arraycopy(exponential, 0, toSign, 0, exponential.length);
//		System.arraycopy(_myGroup, 0, toSign, exponential.length, _myGroup.length);
//
//		return toSign;
//	}

	private byte[] assembleDHParams(byte[] id, byte[] sa) {
		byte[] result = new byte[nonceI.length + nonceR.length + exponentialI.length + exponentialR.length + id.length + sa.length];
		int offset = 0;

		System.arraycopy(nonceI, 0,result,offset,nonceI.length);
		offset += nonceI.length;
		System.arraycopy(nonceR,0 ,result,offset,nonceR.length);
		offset += nonceR.length;
		System.arraycopy(exponentialI, 0, result,offset, exponentialI.length);
		offset += exponentialI.length;
		System.arraycopy(exponentialR, 0, result, offset, exponentialR.length);
		offset += exponentialR.length;
		System.arraycopy(id, 0, result , offset,id.length);
		offset += id.length;
		System.arraycopy(sa, 0, result , offset,sa.length);

		return result;
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
