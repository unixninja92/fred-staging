/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import freenet.crypt.ciphers.Rijndael;

/**
 * CryptBitSet will encrypt and decrypt both byte[]s and BitSets with a specified
 * algorithm, key, and iv. 
*/
public class CryptBitSet {
	public final static CryptBitSetType defaultType = CryptBitSetType.ChaCha;
	private CryptBitSetType type;
	private Cipher cipher;
	private SecretKey key;
	
	private BlockCipher blockCipher;
	private PCFBMode pcfb;
	private byte[] iv;
	
	/**
	 * Creates an instance of CryptBitSet that will be able to encrypt and decrypt 
	 * sets of bytes using the algorithm type with the specified key.
	 * @param type The symmetric algorithm, mode, and key and block size to use
	 * @param key The key that will be used for encryption
	 */
	public CryptBitSet(CryptBitSetType type, SecretKey key){
		this.type = type;

		try {
			if(type.cipherName == "AES"){
				cipher = Cipher.getInstance(type.algName, PreferredAlgorithms.aesCTRProvider);
				this.key = key;
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public CryptBitSet(CryptBitSetType type, byte[] key){
		this(type, KeyUtils.getSecretKey(key, type.keyType));
	}
	
	
	/**
	 * Creates an instance of CryptBitSet that will be able to encrypt and decrypt 
	 * sets of bytes using the algorithm type with the specified key and iv.
	 * @param type
	 * @param key
	 * @param iv
	 */
	public CryptBitSet(CryptBitSetType type, SecretKey key, byte[] iv) {
		this.type = type;
		this.key = key;
		this.iv = iv;
		try{
			if(type == CryptBitSetType.RijndaelPCFB){
				blockCipher = new Rijndael(type.keyType.keySize, type.blockSize);
				blockCipher.initialize(key.getEncoded());
				pcfb = PCFBMode.create(blockCipher, iv);
			}
		} catch (UnsupportedCipherException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public CryptBitSet(CryptBitSetType type, byte[] key, byte[] iv) {
		this(type, KeyUtils.getSecretKey(key, type.keyType), iv);
	}

	/**
	 * Encrypts or decrypts a specified section of input.
	 * @param mode Sets mode to either encrypt or decrypt. 0 for decryption,
	 * 1 for encryption.
	 * @param input The byte[] to be processes(either encrypted or decrypted)
	 * @param offset The position in the byte[] to start processing at
	 * @param len How many more bytes to process in the array past offset
	 * @return Depending on the value of mode will either return an encrypted
	 * or decrypted version of the selected portion of the byte[] input
	 */
	private byte[] processesBytes(int mode, byte[] input, int offset, int len){
		try {
			if(type.cipherName == "Rijndael"){
				if(mode == 0){
					switch(type){
					case RijndaelPCFB:
						return pcfb.blockDecipher(input, offset, len);
					case RijndaelECB:
						break;
					case RijndaelECB128:
						break;
					case RijndaelCTR:
						break;
					}
				}
				else{
					switch(type){
					case RijndaelPCFB:
						return pcfb.blockEncipher(input, offset, len);
					case RijndaelECB:
						break;
					case RijndaelECB128:
						break;
					case RijndaelCTR:
						break;
					}
				}
			}
			else if(type.cipherName == "AES"){
				cipher.init(mode, key);
				return cipher.doFinal(input, offset, len);
			}
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Encrypts the specified section of input
	 * @param input The bytes to be encrypted
	 * @param offset The position of input to start encrypting at
	 * @param len The number of bytes after offset to encrypt
	 * @return Returns byte[] input with the specified section encrypted
	 */
	public byte[] encrypt(byte[] input, int offset, int len){
		return processesBytes(1, input, offset, len);
	}
	
	
	public byte[] encrypt(byte[] input){
		return encrypt(input, 0, input.length);
	}
	
	public BitSet encrypt(BitSet input){
		return BitSet.valueOf(encrypt(input.toByteArray()));
	}
	
	public byte[] decrypt(byte[] input, int offset, int len){
		return processesBytes(0, input, offset, len);
	}
	
	public byte[] decrypt(byte[] input){
		return decrypt(input, 0, input.length);
	}
	
	public BitSet decrypt(BitSet input){
		return BitSet.valueOf(decrypt(input.toByteArray()));
	}
}
