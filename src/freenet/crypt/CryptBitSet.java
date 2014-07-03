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

public class CryptBitSet {
	public final static CryptBitSetType defaultType = CryptBitSetType.ChaCha;
	private CryptBitSetType type;
	private Cipher cipher;
	private SecretKey key;
	private BitSet encryptedData;
	
	private BlockCipher bCipher;
	private PCFBMode pcfb;
	
	private byte[] iv;
	
	public CryptBitSet(CryptBitSetType type, SecretKey key) throws InvalidKeyException{
		this.type = type;

		try {
			if(type.cipherName == "AES"){
				cipher = Cipher.getInstance(type.algName, PreferredAlgorithms.aesCTRProvider);
				cipher.init(0, KeyUtils.getSecretKey(key.getEncoded(), type.keyType));
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public CryptBitSet(CryptBitSetType rijndaelpcfb, byte[] key, byte[] iv) {
		try{
			if(type == CryptBitSetType.RijndaelPCFB){
				bCipher = new Rijndael(type.keyType.keySize, type.blockSize);
				bCipher.initialize(key);
				pcfb = PCFBMode.create(bCipher, iv);
			}
		} catch (UnsupportedCipherException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

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
