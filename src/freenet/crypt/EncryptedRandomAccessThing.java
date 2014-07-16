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
	private SkippingStreamCipher cipherRead;
	private SkippingStreamCipher cipherWrite; 
	private KeyParameter key;
	private IvParameterSpec iv;
	private ParametersWithIV cipherParams;
	
	public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, RandomAccessThing underlyingThing, SecretKey key, IvParameterSpec iv){
		this.type = type;
		this.underlyingThing = underlyingThing;
		this.cipherRead = this.type.get();
		this.cipherWrite = this.type.get();
		this.key = new KeyParameter(key.getEncoded());
		this.iv = iv;
		this.cipherParams = new ParametersWithIV(this.key, iv.getIV());
		
		cipherRead.init(false, cipherParams);
		cipherWrite.init(true, cipherParams);
	}
	
	@Override
	public long size() throws IOException {
		return underlyingThing.size();
	}

	@Override
	public void pread(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
		cipherRead.seekTo(fileOffset);
		
		byte[] cipherText = new byte[length];
		underlyingThing.pread(fileOffset, cipherText, 0, length);
		cipherRead.processBytes(buf, 0, length, buf, bufOffset);
	}

	@Override
	public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
		cipherWrite.seekTo(fileOffset);
		
		byte[] cipherText = new byte[length];
		cipherWrite.processBytes(buf, bufOffset, length, cipherText, 0);
		underlyingThing.pwrite(fileOffset, cipherText, 0, length);
	}

	@Override
	public void close() {
		underlyingThing.close();
		cipherRead = null;
		cipherWrite = null;
		key = null;
		iv = null;
		cipherParams = null;
	}

}
