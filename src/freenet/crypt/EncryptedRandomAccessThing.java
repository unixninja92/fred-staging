package freenet.crypt;

import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SkippingStreamCipher;

import freenet.support.io.RandomAccessThing;
/**
 * REQUIRES BC 151 OR NEWER!!!!!! 
 * @author unixninja92
 *
 */
public final class EncryptedRandomAccessThing implements RandomAccessThing {
	private EncryptedRandomAccessThingType type;
	private RandomAccessThing underlyingThing;
	private SkippingStreamCipher cipher; 
	private CipherParameters key;
	
	public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, RandomAccessThing underlyingThing, SecretKey key){
		this.type = type;
		this.underlyingThing = underlyingThing;
		this.cipher = this.type.get();
//		this.key =  KeyParameters(key, new IvParameterSpec(new byte[8]));
	}
	
	@Override
	public long size() throws IOException {
		return underlyingThing.size();
	}

	@Override
	public void pread(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
//		cipher.init(Cipher.DECRYPT_MODE, key);

	}

	@Override
	public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

}
