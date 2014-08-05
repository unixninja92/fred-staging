package freenet.crypt;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import freenet.support.HexUtil;
import freenet.support.Logger;

public class KeyGenUtilsTest {
    private static final int trueLength = 16;
    private static final int falseLength = -1;
    private static final KeyType[] keyTypes = KeyType.values();
    private static final byte[][] trueSecretKeys = {
        HexUtil.hexToBytes("20e86dc31ebf2c0e37670e30f8f45c57"),
        HexUtil.hexToBytes("8c6c2e0a60b3b73e9dbef076b68b686bacc9d20081e8822725d14b10b5034f48"),
        HexUtil.hexToBytes("33a4a38b71c8e350d3a98357d1bc9ecd"),
        HexUtil.hexToBytes("be56dbec20bff9f6f343800367287b48c0c28bf47f14b46aad3a32e4f24f0f5e"),
        HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        HexUtil.hexToBytes("a92e3fa63e8cbe50869fb352d883911271bf2b0e9048ad04c013b20e901f5806"),
        HexUtil.hexToBytes("45d6c9656b3b115263ba12739e90dcc1"),
        HexUtil.hexToBytes("f468986cbaeecabd4cf242607ac602b51a1adaf4f9a4fc5b298970cbda0b55c6")
    };

    private static final KeyPairType[] trueKeyPairTypes = {KeyPairType.ECP256, 
        KeyPairType.ECP384, KeyPairType.ECP521};
    @SuppressWarnings("deprecation")
    private static final KeyPairType falseKeyPairType = KeyPairType.DSA;
    private static final byte[][] truePublicKeys = {
        HexUtil.hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200040126491fbe391419f"
                + "cdca058122a8520a816d3b7af9bc3a3af038e455b311b8234e5915ae2da11550a9f0ff9da5c65257"
                + "c95c2bd3d5c21bcf16f6c15a94a50cb"),
        HexUtil.hexToBytes("3076301006072a8648ce3d020106052b81040022036200043a095518fc49cfaf6feb5af"
                + "01cf71c02ebfff4fe581d93c6e252c8c607e6568db7267e0b958c4a262a6e6fa7c18572c3af59cd1"
                + "6535a28759d04488bae6c3014bbb4b89c25cbe3b76d7b540dabb13aed5793eb3ce572811b560bb18"
                + "b00a5ac93"),
        HexUtil.hexToBytes("30819b301006072a8648ce3d020106052b8104002303818600040076083359c8b0b34a9"
                + "03461e435188cb90f7501bcb7ed97e8c506c5b60ff21178a625f80f5729ed4746d8e83b28145a51b"
                + "9495880bf41b8ff0746ea0fe684832cc100ef1b01793c84abf64f31452d95bf0ef43d32440d8bc0d"
                + "67501fcffaf51ae4956e5ff22f3baffea5edddbebbeed0ec3b4af28d18568aaf97b5cd026f675388"
                + "1e0c4")
    };
    private static PublicKey[] publicKeys = new PublicKey[truePublicKeys.length];
    private static final byte[][] truePrivateKeys = {
        HexUtil.hexToBytes("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420f"
                + "8cb4b29aa51153ba811461e93fd1b2e69a127972f7100c5e246a3b2dcdd1b1c"),
        HexUtil.hexToBytes("304e020100301006072a8648ce3d020106052b81040022043730350201010430b88fe05"
                + "d03b20dca95f19cb0fbabdfef1211452b29527ccac2ea37236d31ab6e7cada08315c62912b5c17cd"
                + "f2d87fa3d"),
        HexUtil.hexToBytes("3060020100301006072a8648ce3d020106052b8104002304493047020101044201b4f57"
                + "3157d51f2e64a8b465fa92e52bae3529270951d448c18e4967beaa04b1f1fedb0e7a1e26f2eefb30"
                + "566a479e1194358670b044fae438d11717eb2a795c3a8")
    };
    private static PrivateKey[] privateKeys = new PrivateKey[truePublicKeys.length];

    private static final byte[] trueIV = new byte[16];
    
    private static final String kdfInput = "testKey";

    static{
        Security.addProvider(new BouncyCastleProvider());
        KeyPairType type;
        KeyFactory kf;
        X509EncodedKeySpec xks;
        PKCS8EncodedKeySpec pks;
        for(int i = 0; i < trueKeyPairTypes.length; i++){ 
            try {
                type = trueKeyPairTypes[i];
                kf = KeyFactory.getInstance(type.alg);
                xks = new X509EncodedKeySpec(truePublicKeys[i]);
                publicKeys[i] = kf.generatePublic(xks);
                pks = new PKCS8EncodedKeySpec(truePrivateKeys[i]);
                privateKeys[i] = kf.generatePrivate(pks);
            } catch (GeneralSecurityException e) {
                Logger.error(KeyGenUtils.class, "Internal error; please report:", e);
            }
        }
    }

    @Test
    public void testGenKeyPair() {
        for(KeyPairType type: trueKeyPairTypes){
            assertNotNull("KeyPairType: "+type.name(), KeyGenUtils.genKeyPair(type));
        }
    }

    @Test
    public void testGenKeyPairPublicKeyLength() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPairType type = trueKeyPairTypes[i];
            byte[] publicKey = KeyGenUtils.genKeyPair(type).getPublic().getEncoded();
            assertEquals("KeyPairType: "+type.name(), truePublicKeys[i].length, publicKey.length);
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGenKeyPairDSAType() {
        KeyGenUtils.genKeyPair(falseKeyPairType);
    }

    @Test (expected = NullPointerException.class)
    public void testGenKeyPairNullInput() {
        KeyGenUtils.genKeyPair(null);
    }

    @Test
    public void testGetPublicKey() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPairType type = trueKeyPairTypes[i];
            PublicKey key = KeyGenUtils.getPublicKey(type, truePublicKeys[i]);
            assertArrayEquals("KeyPairType: "+type.name(), key.getEncoded(), truePublicKeys[i]);
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGetPublicKeyDSAType() {
        KeyGenUtils.getPublicKey(falseKeyPairType, null);
    }

    @Test (expected = NullPointerException.class)
    public void testGetPublicKeyNullInput1() {
        KeyGenUtils.getPublicKey(null, truePublicKeys[0]);
    }

    @Test (expected = NullPointerException.class)
    public void testGetPublicKeyNullInput2() {
        KeyGenUtils.getPublicKey(trueKeyPairTypes[0], null);
    }

    @Test
    public void testGetPublicKeyPair() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPairType type = trueKeyPairTypes[i];
            KeyPair key = KeyGenUtils.getPublicKeyPair(type, truePublicKeys[i]);
            assertArrayEquals("KeyPairType: "+type.name(), key.getPublic().getEncoded(), 
                    truePublicKeys[i]);
            assertNull("KeyPairType: "+type.name(), key.getPrivate());
        }
    }

    @Test
    public void testGetPublicKeyPairNotNull() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPairType type = trueKeyPairTypes[i];
            assertNotNull("KeyPairType: "+type.name(), KeyGenUtils.getPublicKey(type, 
                    truePublicKeys[i]));
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGetPublicKeyPairDSAType() {
        KeyGenUtils.getPublicKeyPair(falseKeyPairType, null);
    }

    @Test (expected = NullPointerException.class)
    public void testGetPublicKeyPairNullInput1() {
        KeyGenUtils.getPublicKeyPair(null, truePublicKeys[0]);
    }

    @Test (expected = NullPointerException.class)
    public void testGetPublicKeyPairNullInput2() {
        KeyGenUtils.getPublicKeyPair(trueKeyPairTypes[0], null);
    }

    @Test
    public void testGetKeyPairKeyPairTypeByteArrayByteArray() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPairType type = trueKeyPairTypes[i];
            assertNotNull("KeyPairType: "+type.name(), 
                    KeyGenUtils.getKeyPair(type, truePublicKeys[i], truePrivateKeys[i]));
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGetKeyPairKeyPairTypeByteArrayDSAType() {
        KeyGenUtils.getKeyPair(falseKeyPairType, null, null);
    }

    @Test (expected = NullPointerException.class)
    public void testGetKeyPairKeyPairTypeByteArrayNullInput1() {
        KeyGenUtils.getKeyPair(null, truePublicKeys[0], truePrivateKeys[0]);
    }

    @Test (expected = NullPointerException.class)
    public void testGetKeyPairKeyPairTypeByteArrayNullInput2() {
        KeyGenUtils.getKeyPair(trueKeyPairTypes[0], null, truePrivateKeys[0]);
    }

    @Test (expected = NullPointerException.class)
    public void testGetKeyPairKeyPairTypeByteArrayNullInput3() {
        KeyGenUtils.getKeyPair(trueKeyPairTypes[0], truePublicKeys[0], null);
    }

    @Test
    public void testGetKeyPairPublicKeyPrivateKey() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            assertNotNull("KeyPairType: "+trueKeyPairTypes[i].name(), 
                    KeyGenUtils.getKeyPair(publicKeys[i], privateKeys[i]));
        }
    }

    @Test
    public void testGetKeyPairPublicKeyPrivateKeySamePublic() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPair pair = KeyGenUtils.getKeyPair(publicKeys[i], privateKeys[i]);
            assertEquals("KeyPairType: "+trueKeyPairTypes[i].name(), 
                    pair.getPublic(), publicKeys[i]);
        }
    }

    @Test
    public void testGetKeyPairPublicKeyPrivateKeySamePrivate() {
        for(int i = 0; i < trueKeyPairTypes.length; i++){
            KeyPair pair = KeyGenUtils.getKeyPair(publicKeys[i], privateKeys[i]);
            assertEquals("KeyPairType: "+trueKeyPairTypes[i].name(), 
                    pair.getPrivate(), privateKeys[i]);
        }
    }

    @Test
    public void testGenSecretKey() {
        for(KeyType type: keyTypes){
            assertNotNull("KeyType: "+type.name(), KeyGenUtils.genSecretKey(type));
        }
    }

    @Test
    public void testGenSecretKeyKeySize() {
        for(KeyType type: keyTypes){
            byte[] key = KeyGenUtils.genSecretKey(type).getEncoded();
            int keySizeBytes = type.keySize >> 3;
            assertEquals("KeyType: "+type.name(), keySizeBytes, key.length);
        }
    }

    @Test (expected = NullPointerException.class)
    public void testGenSecretKeyNullInput() {
        KeyGenUtils.genSecretKey(null);
    }

    @Test
    public void testGetSecretKey() {
        for(int i = 0; i < keyTypes.length; i++){
            KeyType type = keyTypes[i];
            SecretKey newKey = KeyGenUtils.getSecretKey(type, trueSecretKeys[i]);
            assertArrayEquals("KeyType: "+type.name(), trueSecretKeys[i], newKey.getEncoded());
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void testGetSecretKeyNullInput1() {
        KeyGenUtils.getSecretKey(keyTypes[1], null);
    }

    @Test (expected = NullPointerException.class)
    public void testGetSecretKeyNullInput2() {
        KeyGenUtils.getSecretKey(null, trueSecretKeys[0]);
    }

    @Test
    public void testGenNonceLength() {
        assertEquals(KeyGenUtils.genNonce(trueLength).array().length, trueLength);
    }

    @Test (expected = NegativeArraySizeException.class)
    public void testGenNonceNegativeLength() {
        KeyGenUtils.genNonce(falseLength);
    }

    @Test
    public void testGenIV() {
        assertEquals(KeyGenUtils.genIV(trueLength).getIV().length, trueLength);
    }

    @Test (expected = NegativeArraySizeException.class)
    public void testGenIVNegativeLength() {
        KeyGenUtils.genIV(falseLength);
    }

    @Test
    public void testGetIvParameterSpecLength() {
        assertEquals(KeyGenUtils.getIvParameterSpec(new byte[16], 0, trueLength).getIV().length, 
                trueLength);
    }

    @Test (expected = IllegalArgumentException.class)
    public void testGetIvParameterSpecNullInput() {
        KeyGenUtils.getIvParameterSpec(null, 0, trueIV.length);
    }

    @Test (expected = ArrayIndexOutOfBoundsException.class)
    public void testGetIvParameterSpecOffsetOutOfBounds() {
        KeyGenUtils.getIvParameterSpec(trueIV, -4, trueIV.length);
    }

    @Test (expected = IllegalArgumentException.class)
    public void testGetIvParameterSpecLengthOutOfBounds() {
        KeyGenUtils.getIvParameterSpec(trueIV, 0, trueIV.length+20);
    }
    
    @Test
    public void testDeriveKey() throws InvalidKeyException{
        SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMACSHA512, trueSecretKeys[6]);
        ByteBuffer buf1 = KeyGenUtils.deriveKey(kdfKey, KeyGenUtils.class, kdfInput);
        ByteBuffer buf2 = KeyGenUtils.deriveKey(kdfKey, KeyGenUtils.class, kdfInput);
        assertTrue(buf1.equals(buf2));
    }
    
    @Test (expected = InvalidKeyException.class)
    public void testDeriveKeyNullInput1() throws InvalidKeyException {
        SecretKey kdfKey = null;
        KeyGenUtils.deriveKey(kdfKey, KeyGenUtils.class, kdfInput);
    }

    @Test (expected = NullPointerException.class)
    public void testDeriveKeyNullInput2() throws InvalidKeyException{
        SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMACSHA512, trueSecretKeys[6]);
        KeyGenUtils.deriveKey(kdfKey, null, kdfInput);
    }

    @Test (expected = NullPointerException.class)
    public void testDeriveKeyNullInput3() throws InvalidKeyException{
        SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMACSHA512, trueSecretKeys[6]);
        KeyGenUtils.deriveKey(kdfKey, KeyGenUtils.class, null);
    }
    
    @Test (expected = IndexOutOfBoundsException.class)
    public void testDeriveKeyTruncatedLenOutOfBounds() throws InvalidKeyException{
        SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMACSHA512, trueSecretKeys[6]);
        KeyGenUtils.deriveKeyTruncated(kdfKey, KeyGenUtils.class, kdfInput, -1);
    }
}