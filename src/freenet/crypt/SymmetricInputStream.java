package freenet.crypt;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import freenet.crypt.ciphers.Rijndael;

public class SymmetricInputStream extends FilterInputStream {
	private CryptBucketType type;
    
	private Cipher cipher;
	
	private BlockCipher bCipher;
	private PCFBMode pcfb;
	
	private byte[] iv;
	
	protected SymmetricInputStream(InputStream in, CryptBucketType type, byte[] key, int ivSize) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedCipherException, IOException {
		super(in);
		iv = new byte[ivSize];
		new DataInputStream(in).readFully(iv);
		this.type = type;
		if(type.cipherName == "AES"){
			cipher = Cipher.getInstance(type.algName, PreferredAlgorithms.aesCTRProvider);
			cipher.init(0, KeyUtils.getSecretKey(key, type.keyType));
		}
		else if(type == CryptBucketType.RijndaelPCFB){
			bCipher = new Rijndael(type.keySize, type.blockSize);
			bCipher.initialize(key);
			pcfb = PCFBMode.create(bCipher, iv);
		}
	}
	
	public final int getIVSize() {
        return iv.length;
    }
	
    @Override
    public int read() throws IOException {
        return -1;
    }
    
    @Override
    public int read(byte[] buf) throws IOException {
        return read(buf, 0, buf.length);
    }
    
    @Override
    public int read(byte[] clearText, int offset, int length) throws IOException {
        if(length < 0) return -1;
        if(length == 0) return 0;
        int avail = available();
        if(length != avail) throw new IOException();//switch to different exception?
        byte[] cipherText = new byte[avail];
        in.read(cipherText);
//        byte[] cleartext;
		if(type.cipherName == "AES"){
			try {
				clearText = cipher.doFinal(cipherText);
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else if(type == CryptBucketType.RijndaelPCFB){
			clearText = pcfb.blockDecipher(cipherText, offset, length);
		}
		return 0;
    }
    
    @Override
    public boolean markSupported() {
        return false;
    }
    
    @Override
    public void mark(int readlimit) {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public void reset() throws IOException {
        throw new IOException("Mark/reset not supported");
    }

}
