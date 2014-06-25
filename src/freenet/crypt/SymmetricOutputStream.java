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
	private byte[] plainText;

	public SymmetricOutputStream(OutputStream out, CryptBucketType type, byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedCipherException, InvalidKeyException, IOException {
		super(out);
		out.write(iv);
		this.type = type;
		if(type.cipherName == "AES"){
			cipher = Cipher.getInstance(type.algName, PreferredAlgorithms.aesCTRProvider);
			//FIXME should gen with IV
//			cipher.init(0, KeyUtils.getSecretKey(key, type.keyType));
		}
		else if(type == CryptBucketType.RijndaelPCFB){
			bCipher = new Rijndael(type.keySize, type.blockSize);
			bCipher.initialize(key);
			
			pcfb = PCFBMode.create(bCipher, iv);
			
			plainText = new byte[0];
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
    		output = cipher.update(buf, offset, length);
    	}
    	else if(type == CryptBucketType.RijndaelPCFB){
    		byte[] first = new byte[plainText.length];
    		System.arraycopy(plainText, 0, first, 0, plainText.length);
    		plainText = new byte[first.length+length];
    		return;
    	}
		out.write(output);
    }

    @Override
    public void close() throws IOException {
        byte[] output = null;
    	if(type.cipherName == "AES"){
    		output = new byte[cipher.getOutputSize(0)];
    		try {
    			cipher.doFinal(output, 0);
    		} catch (IllegalBlockSizeException | ShortBufferException | 
    				BadPaddingException e) {
    			// Impossible???
    			throw new RuntimeException("Impossible: "+e);
    		}
    	}
		else if(type == CryptBucketType.RijndaelPCFB){
			output = pcfb.blockEncipher(plainText, 0, plainText.length);
			
		}
        out.write(output);
        out.close();
    }
}
