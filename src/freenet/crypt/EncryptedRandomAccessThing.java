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
    
    private SecretKey headerMacKey;
    private IvParameterSpec headerMacIV;
    
    private boolean isClosed = false;
    
    private SecretKey unencryptedBaseKey;
    
    private MasterSecret masterSecret;
    private SecretKey headerEncKey;
    private byte[] masterIV;
    private int version; 
    
    private static final int IV_LEN = 8;
    private static final int KEY_LEN = 16;
    private static final int MAC_LEN = 16;
    private static final long END_MAGIC = 0x2c158a6c7772acd3L;
    private static final int FOOTER_LENGTH = 52;// in bytes
    
    public EncryptedRandomAccessThing(EncryptedRandomAccessThingType type, 
            RandomAccessThing underlyingThing, MasterSecret masterKey){
        this.type = type;
        this.underlyingThing = underlyingThing;
        this.cipherRead = this.type.get();
        this.cipherWrite = this.type.get();
        this.masterSecret = masterKey;
        this.headerEncKey = this.masterSecret.deriveKey(KeyType.ChaCha256);
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
        
        byte[] encryptedKey = null;
        try {
            CryptBitSet crypt = new CryptBitSet(CryptBitSetType.ChaCha128, headerEncKey, 
                    masterIV);
            encryptedKey = crypt.encrypt(unencryptedBaseKey.getEncoded()).array();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.arraycopy(encryptedKey, 0, footer, offset, encryptedKey.length);
        offset += encryptedKey.length;

        byte[] ver = ByteBuffer.allocate(4).putInt(version).array();
        try {
            MessageAuthCode mac = new MessageAuthCode(MACType.Poly1305AES, headerMacKey, headerMacIV);
            byte[] macResult = mac.genMac(masterIV, unencryptedBaseKey.getEncoded(), ver).array();
            System.arraycopy(macResult, 0, footer, offset, macResult.length);
            offset += macResult.length;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        System.arraycopy(ver, 0, footer, offset, ver.length);
        offset +=ver.length; 
        
        byte[] magic = ByteBuffer.allocate(8).putLong(END_MAGIC).array();
        System.arraycopy(magic, 0, footer, offset, magic.length);
        
        pwrite(size()-FOOTER_LENGTH, footer, 0, FOOTER_LENGTH);
    }
    
    private boolean getVersionCheckMagic() throws IOException{
        int len = 12;
        byte[] footer = new byte[len];
        int offset = 0;
        pread(size()-len, footer, offset, len);
        
        version = ByteBuffer.wrap(footer, offset, 4).getInt();
        offset += 4;
        
        if(END_MAGIC != ByteBuffer.wrap(footer, offset, 8).getLong()){
            return false;
        }
        return true;
    }
    
    private boolean readFooter() throws IOException {
        byte[] footer = new byte[FOOTER_LENGTH-12];
        int offset = 0;
        pread(size()-FOOTER_LENGTH, footer, offset, FOOTER_LENGTH-12);
        
        masterIV = new byte[CryptBitSetType.ChaCha128.ivSize];
        System.arraycopy(footer, offset, masterIV, 0, masterIV.length);
        offset += masterIV.length;
        
        byte[] encryptedKey = new byte[KEY_LEN];
        System.arraycopy(footer, offset, encryptedKey, 0, KEY_LEN);
        offset += KEY_LEN;
        try {
            CryptBitSet crypt = new CryptBitSet(CryptBitSetType.ChaCha128, headerEncKey, 
                    masterIV);
            unencryptedBaseKey = KeyGenUtils.getSecretKey(KeyType.HMACSHA512, 
                    crypt.decrypt(unencryptedBaseKey.getEncoded()));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException();
        }
        
        try {
            headerMacKey = masterSecret.deriveKey(MACType.Poly1305AES.keyType);
            headerMacIV = KeyGenUtils.deriveIvParameterSpec(unencryptedBaseKey, this.getClass(), 
                    kdfInput.macIV.input, MACType.Poly1305AES.ivlen);
        } catch (InvalidKeyException e1) {
            throw new IOException();
        }
        
        byte[] mac = new byte[MAC_LEN];
        System.arraycopy(footer, offset, mac, 0, MAC_LEN);
        
        byte[] ver = ByteBuffer.allocate(4).putInt(version).array();
        try{
            MessageAuthCode authcode = new MessageAuthCode(MACType.Poly1305AES, headerMacKey, headerMacIV);
            return authcode.verifyData(mac, masterIV, unencryptedBaseKey.getEncoded(), ver);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException();
        }
    }
    
    private enum kdfInput {
        baseIV(),
        underlyingKey(),
        underlyingIV(),
        macKey(),
        macIV();
        
        public final String input;
        
        private kdfInput(){
            this.input = this.getClass().getName()+name();
        }
        
    }

}
