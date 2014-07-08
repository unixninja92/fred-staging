/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;

import freenet.support.Logger;

/**
 * Generates Message Authentication Codes for blobs of bytes using a specified algorithm.
 * @author unixninja92
 *
 */
public final class MessageAuthCode {
	private static final MACType defaultType = PreferredAlgorithms.preferredMAC;
	private MACType type;
	private Mac mac;
	private SecretKey key;
	private IvParameterSpec iv;
	
	/**
	 * Creates an instance of MessageAuthCode that will use the specified algorithm and 
	 * key. If that algorithms requires an IV it will generate one. 
	 * @param type The MAC algorithm to use
	 * @param cryptoKey The key to use
	 * @throws InvalidKeyException
	 */
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
	
	/**
	 * Creates an instance of MessageAuthCode that will use the specified algorithm and 
	 * key which is converted from a byte[] to a SecretKey. If that algorithms requires 
	 * an IV it will generate one. 
	 * @param type The MAC algorithm to use
	 * @param cryptoKey The key to use
	 * @throws InvalidKeyException
	 */
	public MessageAuthCode(MACType type, byte[] cryptoKey) throws InvalidKeyException {
		this(type, KeyUtils.getSecretKey(cryptoKey, type.keyType));	
	}
	
	/**
	 * Creates an instance of MessageAuthCode that will use the specified algorithm and 
	 * will generate a key. If that algorithms requires an IV it will generate one. 
	 * @param type The MAC algorithm to 
	 * @throws InvalidKeyException
	 */
	public MessageAuthCode(MACType type) throws InvalidKeyException{
		this(type, KeyUtils.genSecretKey(type.keyType));
	}

	/**
	 * Creates an instance of MessageAuthCode that will use the default algorithm and 
	 * will generate a key. If that algorithms requires an IV it will generate one. 
	 * @param type The MAC algorithm to 
	 * @throws InvalidKeyException
	 */
	public MessageAuthCode() throws InvalidKeyException{
		this(defaultType);
	}
	
	/**
	 * Creates an instance of MessageAuthCode that will use Poly1305 with the specified 
	 * key and iv.
	 * @param key They key to be used
	 * @param iv The iv to be used
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
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
	
	/**
	 * Creates an instance of MessageAuthCode that will use Poly1305 with the specified 
	 * key and iv.
	 * @param key They key to be used as a byte[]
	 * @param iv The iv to be used
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public MessageAuthCode(byte[] key, IvParameterSpec iv) throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedTypeException{
		this(KeyUtils.getSecretKey(key, defaultType.keyType), iv);
	}

	/**
	 * Creates an instance of MessageAuthCode that will use Poly1305 with the specified 
	 * key and iv.
	 * @param key They key to be used 
	 * @param iv The iv to be used as a byte[]
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public MessageAuthCode(SecretKey key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedTypeException{
		this(key, new IvParameterSpec(iv, 0, 16));
	}

	/**
	 * Creates an instance of MessageAuthCode that will use Poly1305 with the specified 
	 * key and iv.
	 * @param key They key to be used as a byte[]
	 * @param iv The iv to be used as a byte[]
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public MessageAuthCode(byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedTypeException{
		this(KeyUtils.getSecretKey(key, defaultType.keyType), iv);
	}
	
	/**
	 * Checks to make sure the provided key is a valid Poly1305 key
	 * @param encodedKey Key to check
	 * @throws UnsupportedTypeException
	 */
	private final void checkPoly1305Key(byte[] encodedKey) throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		Poly1305KeyGenerator.checkKey(encodedKey);
	}
	
	/**
	 * Adds a byte to the buffer of data to be used for MAC generation
	 * @param input The byte to add
	 */
	public final void addByte(byte input){
		mac.update(input);
	}
	
	/**
	 * Adds byte[]s to the buffer of data to be used for MAC generation
	 * @param input The byte[]s to add
	 */
	public final void addBytes(byte[]... input){
		for(byte[] b: input){
			mac.update(b);
		}
	}
	
	/**
	 * Adds the data in a ByteBuffer to the buffer of data to be 
	 * used for MAC generation
	 * @param input The ByteBuffer to be added
	 */
	public final void addBytes(ByteBuffer input){
		mac.update(input);
	}
	
	/**
	 * Adds the specified portion of a byte[] to the buffer of data to 
	 * be used for MAC generation
	 * @param input The byte to add
	 * @param offset What byte to start at
	 * @param len How many bytes after offset to add to buffer
	 */
	public final void addBytes(byte[] input, int offset, int len){
		mac.update(input, offset, len);
	}
	
	/**
	 * Generates a MAC of the data added to the buffer. The buffer is
	 * reset after the MAC is generated.
	 * @return The Message Authentication Code
	 */
	public final byte[] getMac(){
		return mac.doFinal();
	}
	
	/**
	 * Generates a MAC of the given data. The buffer is
	 * reset after the MAC is generated.
	 * @return The Message Authentication Code
	 */
	public final byte[] getMac(byte[]... input){
		addBytes(input);
		return getMac();
	}
	
	/**
	 * Verifies that the two MAC addresses passed in match
	 * @param mac1 First MAC to be verified
	 * @param mac2 Second MAC to be verified
	 * @return Returns true if the MACs match, otherwise false.
	 */
	public final boolean verify(byte[] mac1, byte[] mac2){
		return MessageDigest.isEqual(mac1, mac2);
	}
	
	/**
	 * Verifies that the MAC passed in matches the data provided. 
	 * @param otherMac The MAC to check
	 * @param data The data to check the MAC against
	 * @return Returns true if it is a match, otherwise false.
	 */
	public final boolean verifyData(byte[] otherMac, byte[]... data){
		mac.reset();
		return verify(getMac(data), otherMac);
	}
	
	/**
	 * Gets the key being used
	 * @return Returns the key as a SecretKey
	 */
	public final SecretKey getKey(){
		return key;
	}

	/**
	 * Gets the key being used
	 * @return Returns the key as a byte[]
	 */
	public final byte[] getEncodedKey(){
		return key.getEncoded();
	}
	
	/**
	 * Gets the IV being used. Only works with algorithms that support IVs.
	 * @return Returns the iv as a byte[]
	 * @throws UnsupportedTypeException
	 */
	public final byte[] getIV() throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		return iv.getIV();
	}

	/**
	 * Gets the IV being used. Only works with algorithms that support IVs.
	 * @return Returns the iv as a IvParameterSpec
	 * @throws UnsupportedTypeException
	 */
	public final IvParameterSpec getIVSpec() throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		return iv;
	}

	/**
	 * Changes the current iv to the provided iv. Only works with algorithms that support IVs.
	 * @param iv The new iv to use as IvParameterSpec
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedTypeException
	 */
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
	
	/**
	 * Changes the current iv to the provided iv. Only works with algorithms that support IVs.
	 * @param iv The new iv to use as byte[]
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedTypeException
	 */
	public final void changeIV(byte[] iv) throws InvalidAlgorithmParameterException, UnsupportedTypeException {
		changeIV(new IvParameterSpec(iv, 0, 16));
	}
	
	/**
	 * Generates a new IV to be used. Only works with algorithms that support IVs.
	 * @return The generated IV
	 * @throws UnsupportedTypeException
	 */
	public final IvParameterSpec genIV() throws UnsupportedTypeException{
		if(type != MACType.Poly1305){
			throw new UnsupportedTypeException(type);
		}
		byte[] iV = new byte[type.ivlen];
		PreferredAlgorithms.sRandom.nextBytes(iV);
		this.iv = new IvParameterSpec(iV);
		try {
			mac.init(key, iv);
		} catch (GeneralSecurityException e) {
			Logger.error(MessageAuthCode.class, "Internal error; please report:", e);
		} 
		return this.iv;
	}
}
