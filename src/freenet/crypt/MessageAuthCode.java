/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;

import freenet.support.Logger;

public final class MessageAuthCode {
	private static final MACType defaultType = PreferredAlgorithms.preferredMAC;
	private MACType type;
	private Mac mac;
	private SecretKey key;
	private IvParameterSpec iv;
	
	public MessageAuthCode() throws InvalidKeyException{
		this(defaultType);
	}
	
	public MessageAuthCode(MACType type) throws InvalidKeyException{
		this(type, KeyUtils.genSecretKey(type.keyType));
	}
	
	public MessageAuthCode(MACType type, byte[] cryptoKey) throws InvalidKeyException {
		this(type, KeyUtils.getSecretKey(cryptoKey, type.keyType));	
	}
	
	public MessageAuthCode(MACType type, SecretKey cryptoKey) throws InvalidKeyException {
		this.type = type;
		try {
			mac = type.get();
			key = cryptoKey;
			if(type.ivlen != -1){;
				checkPoly1305Key(key.getEncoded());
				byte[] iV = new byte[type.ivlen];
				PreferredAlgorithms.sRandom.nextBytes(iV);
				this.iv = new IvParameterSpec(iV);
				mac.init(key, iv);
			}
			else{
				mac.init(key);
			}
		}catch (UnsupportedTypeException e) {
			Logger.error(MessageAuthCode.class, "Internal error; please report:", e);
		} catch (InvalidAlgorithmParameterException e) {
			Logger.error(MessageAuthCode.class, "Internal error; please report:", e);
		}
	}
	
	public MessageAuthCode(byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException{
		this(KeyUtils.getSecretKey(key, defaultType.keyType), iv);
	}
	
	public MessageAuthCode(byte[] key, IvParameterSpec iv) throws InvalidKeyException, InvalidAlgorithmParameterException{
		this(KeyUtils.getSecretKey(key, defaultType.keyType), iv);
	}
	
	public MessageAuthCode(SecretKey key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException{
		this(key, new IvParameterSpec(iv, 0, 16));
	}
	
	public MessageAuthCode(SecretKey key, IvParameterSpec iv) throws InvalidKeyException, InvalidAlgorithmParameterException{
		type = defaultType;
		try{
			mac = type.get();
			checkPoly1305Key(key.getEncoded());
			this.key = key;
			this.iv = iv;
			mac.init(key, this.iv);
		} catch (UnsupportedTypeException e) {
			Logger.error(MessageAuthCode.class, "Internal error; please report:", e);
		}
	}
	
	private final void checkPoly1305Key(byte[] encodedKey) throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		Poly1305KeyGenerator.checkKey(encodedKey);
	}
	
	public final void addByte(byte input){
		mac.update(input);
	}
	
	public final void addBytes(byte[]... input){
		for(byte[] b: input){
			mac.update(b);
		}
	}
	
	public final void addBytes(ByteBuffer input){
		mac.update(input);
	}
	
	public final void addBytes(byte[] input, int offset, int len){
		mac.update(input, offset, len);
	}
	
	public final byte[] getMAC(){
		return mac.doFinal();
	}
	
	public final byte[] getMAC(byte[]... input){
		addBytes(input);
		return mac.doFinal();
	}
	
	public final boolean verify(byte[] otherMac){
		return MessageDigest.isEqual(getMAC(), otherMac);
	}
	
	public final boolean verify(byte[] mac1, byte[] mac2){
		return MessageDigest.isEqual(mac1, mac2);
	}
	
	public final boolean verifyData(byte[] otherMac, byte[]... data){
		return MessageDigest.isEqual(getMAC(data), otherMac);
	}
	
	public final SecretKey getKey(){
		return key;
	}
	
	public final byte[] getEncodedKey(){
		return key.getEncoded();
	}
	
	public final byte[] getIV() throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		return iv.getIV();
	}
	
	public final IvParameterSpec getIVSpec() throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		return iv;
	}

	public final void changeIV(IvParameterSpec iv) throws InvalidAlgorithmParameterException, UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		this.iv = iv;
		try {
			mac.init(key, iv);
		} catch (InvalidKeyException e) {
			Logger.error(MessageAuthCode.class, "Internal error; please report:", e);
		}
	}
	
	public final void changeIV(byte[] iv) throws InvalidAlgorithmParameterException, UnsupportedTypeException {
		changeIV(new IvParameterSpec(iv, 0, 16));
	}
}
