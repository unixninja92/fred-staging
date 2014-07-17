/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.util.BitSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import freenet.crypt.ciphers.Rijndael;
import freenet.support.Logger;

/**
 * CryptBitSet will encrypt and decrypt both byte[]s and BitSets with a specified
 * algorithm, key, and also an iv if the algorithm requires one. 
 * @author unixninja92
*/
public final class CryptBitSet {
	public static final CryptBitSetType preferredCryptBitAlg = CryptBitSetType.ChaCha128;
	private final CryptBitSetType type;
	private final SecretKey key;
	private IvParameterSpec iv;

	//Used for AES and ChaCha ciphers
	private Cipher cipher;
	
	//These variables are used with Rijndael ciphers
	private BlockCipher blockCipher;
	private PCFBMode pcfb;
	
	/**
	 * Creates an instance of CryptBitSet that will be able to encrypt and decrypt 
	 * sets of bytes using the algorithm type with the specified key.
	 * @param type The symmetric algorithm, mode, and key and block size to use
	 * @param key The key that will be used for encryption
	 */
	public CryptBitSet(CryptBitSetType type, SecretKey key){
		this.type = type;
		this.key = key;
		try {
			 if(type.cipherName == "Rijndael"){
				blockCipher = new Rijndael(type.keyType.keySize, type.blockSize);
				blockCipher.initialize(key.getEncoded());
				if(type == CryptBitSetType.RijndaelPCFB){
					pcfb = PCFBMode.create(blockCipher, genIV());
				}
			 } 
			 else {
				 cipher = Cipher.getInstance(type.algName);
				 genIV();
			 }
		}  catch (GeneralSecurityException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		} catch (UnsupportedCipherException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		} 
	}
	
	public CryptBitSet(CryptBitSetType type, byte[] key){
		this(type, KeyGenUtils.getSecretKey(key, type.keyType));
	}
	
	public CryptBitSet(CryptBitSetType type){
		this(type, KeyGenUtils.genSecretKey(type.keyType));
	}
	
	
	/**
	 * Creates an instance of CryptBitSet that will be able to encrypt and decrypt 
	 * sets of bytes using the algorithm type with the specified key and iv. Should 
	 * only be used with RijndaelPCFB
	 * @param type
	 * @param key
	 * @param iv
	 * @throws UnsupportedTypeException 
	 */
	public CryptBitSet(CryptBitSetType type, SecretKey key, IvParameterSpec iv){
		if(type.equals(CryptBitSetType.RijndaelECB)|| type.equals(CryptBitSetType.RijndaelECB128)){
			throw new UnsupportedTypeException(type, "Rijndael in ECB mode does not take an IV.");
		}
		this.type = type;
		this.key = key;
		this.iv = iv;
		try{
			if(type == CryptBitSetType.RijndaelPCFB){
				blockCipher = new Rijndael(type.keyType.keySize, type.blockSize);
				blockCipher.initialize(key.getEncoded());
				pcfb = PCFBMode.create(blockCipher, this.iv.getIV());
			} else{
				cipher = Cipher.getInstance(type.algName);
			}
		} catch (GeneralSecurityException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		} catch (UnsupportedCipherException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		}
	}
	
	public CryptBitSet(CryptBitSetType type, SecretKey key, byte[] iv, int offset){
		this(type, key, new IvParameterSpec(iv, offset, type.getIVSize()));
	}
	
	public CryptBitSet(CryptBitSetType type, SecretKey key, byte[] iv){
		this(type, key, iv, 0);
	}
	
	public CryptBitSet(CryptBitSetType type, byte[] key, byte[] iv, int offset){
		this(type, KeyGenUtils.getSecretKey(key, type.keyType), iv, offset);
	}
	
	public CryptBitSet(CryptBitSetType type, byte[] key, byte[] iv){
		this(type, key, iv, 0);
	}

//	/**
//	 * Encrypts or decrypts a specified section of input.
//	 * @param mode Sets mode to either encrypt or decrypt. 0 for decryption,
//	 * 1 for encryption.
//	 * @param input The byte[] to be processes(either encrypted or decrypted)
//	 * @param offset The position in the byte[] to start processing at
//	 * @param len How many more bytes to process in the array past offset
//	 * @return Depending on the value of mode will either return an encrypted
//	 * or decrypted version of the selected portion of the byte[] input
//	 */
//	private byte[] processesBytes(boolean encrypt, byte[] input, int offset, int len){
//		try {
//			if(!encrypt){
//				if(type == CryptBitSetType.RijndaelPCFB){
//					return pcfb.blockDecipher(input, offset, len);
//				} 
//				else if(type.cipherName == "Rijndael"){
//					byte[] actualInput = extractSmallerArray(input, offset, len);
//					byte[] result = new byte[len];
//					blockCipher.decipher(actualInput, result);
//					return result;
//				}
//				else{
//					cipher.init(Cipher.DECRYPT_MODE, key, iv);
//					return cipher.doFinal(input, offset, len);
//				}
//			}
//			else {
//				if(type == CryptBitSetType.RijndaelPCFB){
//					return pcfb.blockEncipher(input, offset, len);
//				} 
//				else if(type.cipherName == "Rijndael"){
//					byte[] actualInput = extractSmallerArray(input, offset, len);
//					byte[] result = new byte[len];
//					blockCipher.encipher(actualInput, result);
//					return result;
//				}
//				else{
//					cipher.init(Cipher.ENCRYPT_MODE, key, iv);
//					return cipher.doFinal(input, offset, len);
//				}
//			}
//		} catch (GeneralSecurityException e) {
//			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
//		} 
//		return null;
//	}
	
	/**
	 * Encrypts the specified section of input
	 * @param input The bytes to be encrypted
	 * @param offset The position of input to start encrypting at
	 * @param len The number of bytes after offset to encrypt
	 * @return Returns byte[] input with the specified section encrypted
	 */
	public byte[] encrypt(byte[] input, int offset, int len){
		try{
			if(type == CryptBitSetType.RijndaelPCFB){
				return pcfb.blockEncipher(input, offset, len);
			} 
			else if(type.cipherName == "Rijndael"){
				byte[] result = new byte[len];
				blockCipher.encipher(extractSmallerArray(input, offset, len), result);
				return result;
			}
			else{
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
				return cipher.doFinal(input, offset, len);
			}
		} catch (GeneralSecurityException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		} 
		return null;
	}
	
	/**
	 * Encrypts the entire byte[] input
	 * @param input The byte[] to be encrypted
	 * @return The encrypted byte[]
	 */
	public byte[] encrypt(byte[] input){
		return encrypt(input, 0, input.length);
	}
	
	/**
	 * Encrypts the BitSet input
	 * @param input The BitSet to encrypt
	 * @return The encrypted BitSet
	 */
	public BitSet encrypt(BitSet input){
		return BitSet.valueOf(encrypt(input.toByteArray()));
	}
	
	/**
	 * Decrypts the specified section of input
	 * @param input The bytes to be decrypted
	 * @param offset The position of input to start decrypting at
	 * @param len The number of bytes after offset to decrypt
	 * @return Returns byte[] input with the specified section decrypted
	 */
	public byte[] decrypt(byte[] input, int offset, int len){
		try{
			if(type == CryptBitSetType.RijndaelPCFB){
				return pcfb.blockDecipher(input, offset, len);
			} 
			else if(type.cipherName == "Rijndael"){
				byte[] result = new byte[len];
				blockCipher.decipher(extractSmallerArray(input, offset, len), result);
				return result;
			}
			else{
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
				return cipher.doFinal(input, offset, len);
			}
		} catch (GeneralSecurityException e) {
			Logger.error(CryptBitSet.class, "Internal error; please report:", e);
		} 
		return null;
	}
	
	/**
	 * Decrypts the entire byte[] input
	 * @param input The byte[] to be decrypted
	 * @return The decrypted byte[]
	 */
	public byte[] decrypt(byte[] input){
		return decrypt(input, 0, input.length);
	}
	
	/**
	 * Decrypts the BitSet input
	 * @param input The BitSet to decrypt
	 * @return The decrypted BitSet
	 */
	public BitSet decrypt(BitSet input){
		return BitSet.valueOf(decrypt(input.toByteArray()));
	}
	
	public void setIV(IvParameterSpec iv){
		this.iv = iv;
	}
	
	public byte[] genIV(){
		this.iv = KeyGenUtils.genIV(type.getIVSize());
		return iv.getIV();
	}
	
	public IvParameterSpec getIV(){
		return iv;
	}
	
	private byte[] extractSmallerArray(byte[] input, int offset, int len){
		if(input.length == len && offset == 0){
			return input;
		}
		else{
			byte[] result = new byte[len];
			System.arraycopy(input, offset, result, 0, len);
			return result;
		}
	}
}
