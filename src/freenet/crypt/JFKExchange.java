package freenet.crypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;

import net.i2p.util.NativeBigInteger;
import freenet.node.PeerNode;

public abstract class JFKExchange {
	protected static final RandomSource rand = PreferredAlgorithms.random;
    protected static volatile boolean logMINOR;
    protected static volatile boolean logDEBUG;
    
	protected byte[] nonceI; //Initiators nonce 
	protected byte[] nonceR; //Responders nonce
	protected byte[] hashnI; //N'i
	protected byte[] hashnR; //N'r
	protected byte[] exponentialI; //Initiators exponential
	protected byte[] exponentialR;//Responders exponential
	protected PeerNode peer;
	protected int modulusLength;
	protected KeyExchange underlyingExch; //IDi and IDr
	
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
	protected static final byte[] JFK_PREFIX_INITIATOR, JFK_PREFIX_RESPONDER;
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
	
	public JFKExchange(KeyExchType underlying, int nonceSize, PeerNode pn){
		this.underlyingExch = new KeyExchange(underlying);
		this.modulusLength = underlyingExch.type.modulusSize;
		this.peer = pn;

		nonceI = new byte[nonceSize];
		rand.nextBytes(nonceI);

		Hash hash = new Hash();
		hashnI = hash.getHash(nonceI);

		exponentialI = underlyingExch.getPublicKeyNetworkFormat();
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

	public byte[] getSharedSecrect(byte[] peerExponential) throws InvalidKeyException{
		if(underlyingExch.type == KeyExchType.DH){
			return underlyingExch.getSharedSecrect(new NativeBigInteger(1, peerExponential));
		}
		else{
			return underlyingExch.getSharedSecrect(KeyUtils.getPublicKey(peerExponential));
		}
	}
	
	
	/*
	 * Assemble what will be the jfk-Authenticator :
	 * computed over the Responder exponentials and the Nonces and
	 * used by the responder to verify that the round-trip has been done
	 *
	 */
	protected byte[] assembleJFKAuthenticator(byte[] address) {
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

	protected byte[] assembleDHParams(byte[] id, byte[] sa) {
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
}
