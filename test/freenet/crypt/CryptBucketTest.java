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
    private static final String key = "000102030405060708090A0B0C0D0E0F";
    public final SecretKey secretKey = KeyGenUtils.getSecretKey(KeyType.AES128, Hex.decode(key));
    private static final String[][] TEST_VECTORS_128 = new String[][]{
        { "BBAA99887766554433221100",
          "",
          "785407BFFFC8AD9EDCC5520AC9111EE6" },
        { "BBAA99887766554433221101",
          "0001020304050607",
          "0001020304050607",
          "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009" },
        { "BBAA99887766554433221103",
          "0001020304050607",
          "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9" },
        { "BBAA99887766554433221104",
          "000102030405060708090A0B0C0D0E0F",
          "000102030405060708090A0B0C0D0E0F",
          "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358" },
        { "BBAA99887766554433221106",
          "000102030405060708090A0B0C0D0E0F",
          "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D" },
        { "BBAA99887766554433221107",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F" },
        { "BBAA99887766554433221108",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "6DC225A071FC1B9F7C69F93B0F1E10DE" },
        { "BBAA99887766554433221109",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF" },
        { "BBAA9988776655443322110C",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF" },
        { "BBAA9988776655443322110F",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479" },
    };
    
    @Test
    public void testSuccessfulRoundTripByteArray() {
        for(CryptBucketType t: types){
            Bucket underlying = new ArrayBucket();
            CryptBucket cb = new CryptBucket(t, underlying, secretKey);
            cb.encryptBytes();
            
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
