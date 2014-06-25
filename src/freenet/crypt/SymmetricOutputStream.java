package freenet.crypt;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.InvalidCipherTextException;

import freenet.crypt.ciphers.Rijndael;

public class SymmetricOutputStream extends FilterOutputStream {
	private CryptBucketType type;
	private Cipher cipher;
	
	private BlockCipher bCipher;
	private PCFBMode pcfb;
	private byte[] iv;

	public SymmetricOutputStream(OutputStream out, CryptBucketType type, byte[] key, byte[] nonce) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedCipherException, InvalidKeyException {
		super(out);
		this.type = type;
		if(type.cipherName == "AES"){
			cipher = Cipher.getInstance(type.algName, PreferredAlgorithms.aesCTRProvider);
			cipher.init(0, KeyUtils.getSecretKey(key, type.keyType));
		}
		else if(type == CryptBucketType.RijndaelPCFB){
			bCipher = new Rijndael(type.keySize, type.blockSize);
			bCipher.initialize(key);
			int ivLength = PCFBMode.lengthIV(bCipher);
			byte[] iv = new byte[ivLength];
			PreferredAlgorithms.random.nextBytes(iv);
			pcfb = PCFBMode.create(bCipher, iv);
		}
	}
	
	@Override
    public void write(int b) throws IOException {
        write(new byte[] { (byte)b });
    }
    
    @Override
    public void write(byte[] buf) throws IOException {
        write(buf, 0, buf.length);
    }
    
    @Override
    public void write(byte[] buf, int offset, int length) throws IOException {
    	byte[] output = null;
    	if(type.cipherName == "AES"){
    		try {
        		output = new byte[cipher.getOutputSize(length)];
				cipher.doFinal(buf, offset, length, output, 0);
			} catch (ShortBufferException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    	else if(type == CryptBucketType.RijndaelPCFB){
    		output = pcfb.blockEncipher(buf, offset, length);
    	}
		out.write(output);
    }

}
