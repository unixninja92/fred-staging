package freenet.crypt;

import java.io.FilterInputStream;
import java.io.InputStream;

import javax.crypto.Cipher;

public class SymmetricInputStream extends FilterInputStream {
	private CryptBucketType type;
    private boolean finished;
    
	private Cipher cipher;
	
	private BlockCipher bCipher;
	private PCFBMode pcfb;
	private byte[] iv;
	
	protected SymmetricInputStream(InputStream in, CryptBucketType type, byte[] key) {
		super(in);
		this.type = type;
		if(type.cipherName == "AES"){
			
		}
		else if(type == CryptBucketType.RijndaelPCFB){
			
		}
	}

}
