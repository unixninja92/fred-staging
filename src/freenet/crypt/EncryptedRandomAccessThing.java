package freenet.crypt;

import java.io.IOException;
import java.util.concurrent.locks.ReentrantLock;

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
    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();
    private final EncryptedRandomAccessThingType type;
    private final RandomAccessThing underlyingThing;
    private SkippingStreamCipher cipherRead;
    private SkippingStreamCipher cipherWrite;
    private ParametersWithIV cipherParams;

    public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, 
            RandomAccessThing underlyingThing, SecretKey key, IvParameterSpec iv){
        this.type = type;
        this.underlyingThing = underlyingThing;
        this.cipherRead = this.type.get();
        this.cipherWrite = this.type.get();
        this.cipherParams = new ParametersWithIV(new KeyParameter(key.getEncoded()), iv.getIV());

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

        byte[] cipherText = new byte[length];
        underlyingThing.pread(fileOffset, cipherText, 0, length);

        readLock.lock();
        try{
            cipherRead.seekTo(fileOffset);
            cipherRead.processBytes(buf, 0, length, buf, bufOffset);
        }finally{
            readLock.unlock();
        }
    }

    @Override
    public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
            throws IOException {
        byte[] cipherText = new byte[length];

        writeLock.lock();
        try{
            cipherWrite.seekTo(fileOffset);
            cipherWrite.processBytes(buf, bufOffset, length, cipherText, 0);
        }finally{
            writeLock.unlock();
        }

        underlyingThing.pwrite(fileOffset, cipherText, 0, length);
    }

    @Override
    public void close() {
        cipherRead = null;
        cipherWrite = null;
        cipherParams = null;
        underlyingThing.close();
    }

}
