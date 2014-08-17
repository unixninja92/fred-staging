package freenet.crypt;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;

public class CryptBucketTest {
    public final CryptBucketType[] types = CryptBucketType.values();
    
//    public final ArrayBucket underlying = new ArrayBucket();
    private static final byte[] message = Hex.decode("000102030405060708090A0B0C0D0E0F");
    
    @Test
    public void testSuccessfulRoundTripByteArray() throws IOException {
        for(CryptBucketType t: types){
            System.out.println(t.name());
            Bucket underlying = new ArrayBucket();
            CryptBucket cb = new CryptBucket(t, underlying, KeyGenUtils.genSecretKey(t.keyType));
            cb.encryptBytes(message);
            assertArrayEquals(message, cb.decrypt());
        }
    }
    
    @Test
    public void testDecrypt() {
        fail("Not yet implemented");
    }

    @Test
    public void testAddByte() {
        fail("Not yet implemented");
    }

    @Test
    public void testAddBytesByteArrayArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testAddBytesByteArrayIntInt() {
        fail("Not yet implemented");
    }

    @Test
    public void testEncrypt() {
        fail("Not yet implemented");
    }

    @Test
    public void testEncryptBytes() {
        fail("Not yet implemented");
    }

    @Test
    public void testGetOutputStream() {
        fail("Not yet implemented");
    }

    @Test
    public void testGetInputStream() {
        fail("Not yet implemented");
    }

    @Test
    public void testGetName() {
        fail("Not yet implemented");
    }

    @Test
    public void testSize() {
        fail("Not yet implemented");
    }

    @Test
    public void testIsReadOnly() {
        fail("Not yet implemented");
    }

    @Test
    public void testSetReadOnly() {
        fail("Not yet implemented");
    }

    @Test
    public void testFree() {
        fail("Not yet implemented");
    }

    @Test
    public void testStoreTo() {
        fail("Not yet implemented");
    }

    @Test
    public void testRemoveFrom() {
        fail("Not yet implemented");
    }

    @Test
    public void testCreateShadow() {
        fail("Not yet implemented");
    }
    
    @Test
    public void testCopyBucketNotDivisibleBy16() throws IOException {
        long length = 902;
        ArrayBucket underlying = new ArrayBucket();
        byte[] key = new byte[16];
        AEADCryptBucket encryptedBucket = new AEADCryptBucket(underlying, key);
        BucketTools.fill(encryptedBucket, length);
        assertEquals(length + AEADCryptBucket.OVERHEAD, underlying.size());
        assertEquals(length, encryptedBucket.size());
        ArrayBucket copyTo = new ArrayBucket();
        BucketTools.copy(encryptedBucket, copyTo);
        assertEquals(length, encryptedBucket.size());
        assertEquals(length, copyTo.size());
        assertTrue(BucketTools.equalBuckets(encryptedBucket, copyTo));
    }

}
