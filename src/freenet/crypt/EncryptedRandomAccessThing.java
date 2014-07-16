package freenet.crypt;

import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import freenet.support.io.RandomAccessThing;
/**
 * REQUIRES BC 151 OR NEWER!!!!!! 
 * @author unixninja92
 *
 */
public final class EncryptedRandomAccessThing implements RandomAccessThing {
	private final EncryptedRandomAccessThingType type;
	private final RandomAccessThing underlyingThing;
	private SkippingStreamCipher cipher; 
	private KeyParameter key;
	private IvParameterSpec iv;
	private ParametersWithIV cipherParams;
	
	public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, RandomAccessThing underlyingThing, SecretKey key, IvParameterSpec iv){
		this.type = type;
		this.underlyingThing = underlyingThing;
		this.cipher = this.type.get();
		this.key = new KeyParameter(key.getEncoded());
		this.iv = iv;
		this.cipherParams = new ParametersWithIV(this.key, iv.getIV());
	}
	
	@Override
	public long size() throws IOException {
		return underlyingThing.size();
	}

	@Override
	public void pread(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
		cipher.init(false, cipherParams);
		cipher.seekTo(fileOffset);
		
		byte[] cipherText = new byte[length];
		underlyingThing.pread(fileOffset, cipherText, 0, length);
		cipher.processBytes(buf, 0, length, buf, bufOffset);
		cipher.reset();
	}

	@Override
	public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
		cipher.init(true, cipherParams);
		cipher.seekTo(fileOffset);
		
		byte[] cipherText = new byte[length];
		cipher.processBytes(buf, bufOffset, length, cipherText, 0);
		underlyingThing.pwrite(fileOffset, cipherText, 0, length);
		cipher.reset();
	}

	@Override
	public void close() {
		underlyingThing.close();
		cipher = null;
		key = null;
		iv = null;
		cipherParams = null;
	}

}
