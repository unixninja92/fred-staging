package freenet.crypt;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import freenet.node.MasterKeys;
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
    private KeyParameter cipherKey;
    private ParametersWithIV cipherParams;//includes key
    
    private SecretKey macKey;
    
    private boolean isClosed = false;
    
    private SecretKey unencryptedBaseKey;
    private IvParameterSpec baseIV;
    
    private SecretKey masterKey;
    private byte[] masterIV;
    private int version; 
    
    private static final int IV_LEN = 8;
    private static final int KEY_LEN = 16;
    private static final int MAC_LEN = 16;
    private static final long END_MAGIC = 0x28b32d99416eb6efL;//should use a different value
    private static final int FOOTER_LENGTH = 52;// in bytes
    
    public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, 
            RandomAccessThing underlyingThing, SecretKey masterKey){
        this.type = type;
        this.underlyingThing = underlyingThing;
        this.cipherRead = this.type.get();
        this.cipherWrite = this.type.get();
        this.masterKey = masterKey;
//        this.cipherParams = new ParametersWithIV(new KeyParameter(key.getEncoded()), iv.getIV());

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
        isClosed = true;
        cipherRead = null;
        cipherWrite = null;
        cipherParams = null;
        underlyingThing.close();
    }
    
    private void writeFooter() throws IOException{
        byte[] footer = new byte[FOOTER_LENGTH];
        int offset = 0;
        
        int ivLen = masterIV.length;
        System.arraycopy(masterIV, 0, footer, offset, ivLen);
        offset += ivLen;
        
        byte[] encryptedKey = encryptBaseKey();
        System.arraycopy(encryptedKey, 0, footer, offset, encryptedKey.length);
        offset += encryptedKey.length;

        byte[] ver = ByteBuffer.allocate(4).putInt(version).array();
        try {
            MessageAuthCode mac = new MessageAuthCode(MACType.HMACSHA256, masterKey);
            byte[] macResult = mac.genMac(masterIV, encryptedKey, ver);
            System.arraycopy(macResult, 0, footer, offset, macResult.length);
            offset += macResult.length;
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        System.arraycopy(ver, 0, footer, offset, ver.length);
        offset +=ver.length; 
        
        byte[] magic = ByteBuffer.allocate(8).putLong(END_MAGIC).array();
        System.arraycopy(magic, 0, footer, offset, magic.length);
        
        pwrite(size()-FOOTER_LENGTH, footer, 0, FOOTER_LENGTH);
    }
    
    private void readFooter() throws IOException {
        byte[] footer = new byte[FOOTER_LENGTH];
        int offset = 0;
        pread(size()-FOOTER_LENGTH, footer, offset, FOOTER_LENGTH);
        
        masterIV = new byte[CryptBitSetType.ChaCha128.ivSize];
        
    }
    
    private byte[] kdf(String keyInfo){
        try {
            MessageAuthCode kdf = new MessageAuthCode(MACType.HMACSHA256, unencryptedBaseKey);
            return kdf.genMac(keyInfo.getBytes("UTF-8"));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    
    private byte[] encryptBaseKey(){
        try {
            CryptBitSet crypt = new CryptBitSet(CryptBitSetType.ChaCha128, masterKey, baseIV);
            return crypt.encrypt(unencryptedBaseKey.getEncoded());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    
    private enum kdfInput {
        baseIV(),
        underlyingKey(),
        underlyingIV(),
        macKey(),
        macIV();
        
    }

}
