/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.util.Arrays;

import freenet.node.PeerNode;
import freenet.support.Logger;

public class JFKReceiver extends JFKExchange {
	public JFKReceiver(KeyExchType underlying, PeerNode peerNode, int nonceSize, byte[] nonceI, byte[] exponentialI){
		super(underlying, nonceSize, peerNode);
		this.processMessage1(nonceSize, nonceI, exponentialI);
	}
	
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
	public final byte[] genMessage2(byte[] transientKey, byte[] replyToAddress, byte[] sig) throws InvalidKeyException{
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

		mac = new MessageAuthCode(MACType.HMACSHA256, transientKey);

		byte[] authenticator = mac.getMac(assembleJFKAuthenticator(replyToAddress));

		System.arraycopy(authenticator, 0, message2, offset, hashnR.length);

		return message2;
	}
	
	
	
	//Processed by reciver
	public byte[] processMessage3(byte[] hmac, byte[] cypheredPayload, int decypheredPayloadOffset, byte[] identity, byte[] publicKeyI) throws InvalidKeyException{
		int blockSize = CryptBitSetType.RijndaelPCFB.blockSize;
		int ivSize = blockSize >> 3;
	    		
		byte[] computedExponential = null;
		try {
			computedExponential = getSharedSecrect(exponentialI);
		} catch (InvalidKeyException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
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
		mac = new MessageAuthCode(MACType.HMACSHA256, jfkKa);
		if(!mac.verifyData(hmac, cypheredPayload)) {
			Logger.error(this, "The inner-HMAC doesn't match; let's discard the packet JFK(3) - "+peer);
			return null;
		}
		
		byte[] iv = new byte[ivSize];
		System.arraycopy(cypheredPayload, decypheredPayloadOffset, iv, 0, ivLength);
		decypheredPayloadOffset += ivLength;
		
		CryptBitSet cryptBits = null;
		try {
			cryptBits = new CryptBitSet(CryptBitSetType.RijndaelPCFB, jfkKe, iv);
		} catch (UnsupportedTypeException e1) {
			Logger.error(KeyExchange.class, "Internal error; please report:", e1);
		}
		byte[] cleartext = cryptBits.decrypt(cypheredPayload, decypheredPayloadOffset, cypheredPayload.length-decypheredPayloadOffset);
	    
	    
	    int sigLength;
	    if(underlyingExch.type == KeyExchType.DH){
	    	sigLength = underlyingExch.dsaSig.length;
	    }
	    else{
	    	sigLength = underlyingExch.ecdsaSig.length;
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
	public byte[] genMessage4(byte[] identity, byte[] data, byte[] refI, byte[] sig, CryptBitSet cryptBits, byte[] newTrackerID, boolean sameAsOldTrackerID, byte[] outgoingBootID, long bootID, SigType sigType) throws InvalidKeyException{
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
		
		cyphertext = cryptBits.decrypt(cyphertext, cleartextToEncypherOffset, cyphertext.length - cleartextToEncypherOffset);
	    	
		// We compute the HMAC of (prefix + iv + signature)
		byte[] hmac = mac.getMac(cyphertext);
		
		byte[] message4 = new byte[hashnI.length + ivLength + (cyphertext.length - cleartextToEncypherOffset)];
		int offset = 0;
		System.arraycopy(hmac, 0, message4, offset, hashnI.length);
		offset += hashnI.length;
		System.arraycopy(iv, 0, message4, offset, ivLength);
		offset += ivLength;
		System.arraycopy(cyphertext, cleartextToEncypherOffset, message4, offset, cyphertext.length - cleartextToEncypherOffset);

		return message4;
	}
}
