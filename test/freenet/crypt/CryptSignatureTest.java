package freenet.crypt;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import freenet.node.NodeStarter;

public class CryptSignatureTest {
    @SuppressWarnings("deprecation")
    private static final SigType dsaType = SigType.DSA;
    private static final DSAPrivateKey dsaPrivateKey = new DSAPrivateKey(Global.DSAgroupBigA, 
            NodeStarter.getGlobalSecureRandom());
    private static final DSAPublicKey dsaPublicKey = new DSAPublicKey(Global.DSAgroupBigA, 
            dsaPrivateKey);

    private static final SigType[] ecdsaTypes = {SigType.ECDSAP256, SigType.ECDSAP384, 
        SigType.ECDSAP512};
    private static final byte[][] publicKeys = 
        { Hex.decode("3059301306072a8648ce3d020106082a8648ce3d0301070342000489865a155b5c1a73c875274"
                + "b6b290325fcee9ddbb2db18ddfa3bc3c3c74ad59e2d98017041856f0835338de51bf11c4ec354f05"
                + "c7ad529c0f86ed0accf5e318f"),
        Hex.decode("3076301006072a8648ce3d020106052b8104002203620004ff548eba3d7cb70665adf0ea9eaa91f"
                + "cd6f18202ee21e3130fab138c02e73f907896f250e3ca6c1f235ba8b5cdea57058958bceb1da141c"
                + "40e4dd23f466766b5f18c96bafcc10a1eed0818e8e41f2170dbe9600d3634f43f60d16f4bea6c9e"
                + "b9"),
        Hex.decode("30819b301006072a8648ce3d020106052b810400230381860004010a2770d3182a7504fc4f8b9f8"
                + "a1fe2f8cc093e2590d9eb8321d43063df1590674262c6c9676c462f80ccb48eabf482b935565dd33"
                + "1a4de733b1fd1c2ea32a14f350184d7e868a0b89ee74f9ba55b90bb2de903794dded4b94980cbcab"
                + "4e66f8d3d3ec90560fb8b93c33e3f78d40f12f362762a7855726a16ff724d18bcb0d469b053e7")
        };
    private static final byte[][] privateKeys =
        { Hex.decode("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420b37e4c5"
                + "3f2b30dbe20fd1fcf3f4fc6b9f367949bb15ada1901f9d101cbecd91e"),
        Hex.decode("304e020100301006072a8648ce3d020106052b81040022043730350201010430f34b6cbcda795a"
                + "8cd0a488249da35e791dfda41f5ca12ef7dc132cf342dce1fb568d5d1dd8c2c12202d73df213224"
                + "b03"),
        Hex.decode("3060020100301006072a8648ce3d020106052b81040023044930470201010442019c70f4538856a"
                + "2eb270a6d99cac7dd0e51e0e56b55dde864291009b6219af0a21be42079481f97df412f288a51976"
                + "6ca600377e8be87931e9d9cf763f0ea86ea98")
        };

    private static KeyPair[] keyPairs = new KeyPair[3];

    private static final byte[] message = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710");
    private static final BigInteger messageBigInteger = new BigInteger(1, message);

    private static final SigType[] types = {dsaType, ecdsaTypes[0], ecdsaTypes[1], ecdsaTypes[2]};

    static{
        Security.addProvider(new BouncyCastleProvider());
        for(int i = 0; i < keyPairs.length; i++){
            keyPairs[i] = KeyGenUtils.getKeyPair(ecdsaTypes[i].keyType, publicKeys[i], 
                    privateKeys[i]);
        }
    }

    @Test
    public void testAddByteToSign() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                for (int j = 0; j < message.length; j++){
                    sig.addByteToSign(message[j]);
                }
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(), message));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddByteToSignVerifyMode() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addByteToSign(message[0]);
                fail("Expected IllegalStateException");
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            } catch (CryptFormatException e) {
                fail("CryptFormatException thrown");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    @SuppressWarnings("null")
    public void testAddByteToSignNullInput() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            Byte b = null;
            try{
                sig.addByteToSign(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddByteToSignUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addByteToSign(message[0]);
    }

    @Test
    public void testAddBytesToSignByteArrayArray() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                sig.addBytesToSign(message);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(), message));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToSignByteArrayArrayNullMatrixInput(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[][] b = null;
            try{
                sig.addBytesToSign(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayArrayNullMatrixElement(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[][] b = {message, null};
            try{
                sig.addBytesToSign(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToSignByteArrayArrayUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToSign(message);
    }

    @Test
    public void testAddBytesToSignByteArrayArrayVerifyMode() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(message);
                fail("Expected IllegalStateException");
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            } catch (CryptFormatException e) {
                fail("CryptFormatException thrown");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntInt() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                sig.addBytesToSign(message, 0, message.length);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(), message));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntNullInput(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[] b = null;
            try{
                sig.addBytesToSign(b, 0, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntOffsetOutOfBounds(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            try{
                sig.addBytesToSign(message, -3, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected ArrayIndexOutOfBoundsException");
            } catch (ArrayIndexOutOfBoundsException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntLengthOutOfBounds(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            try{
                sig.addBytesToSign(message, 0, message.length+3);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToSignByteArrayIntIntUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToSign(message, 0, message.length);
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntVerifyMode() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(message, 0, message.length);
                fail("Expected IllegalStateException");
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            } catch (CryptFormatException e) {
                fail("CryptFormatException thrown");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddBytesToSignByteBuffer() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
                ByteBuffer byteBuffer = ByteBuffer.wrap(message);

                sig.addBytesToSign(byteBuffer);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(), message));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToSignByteBufferNullInput() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
                ByteBuffer byteBuffer = null;

                try{
                    sig.addBytesToSign(byteBuffer);
                    fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
                } catch (NullPointerException e) {}
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToSignByteBufferUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToSign(ByteBuffer.wrap(message));
    }

    @Test
    public void testAddBytesToSignByteBufferVerifyMode() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(ByteBuffer.wrap(message));
                fail("Expected IllegalStateException");
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            } catch (CryptFormatException e) {
                fail("CryptFormatException thrown");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddByteToVerify() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                for (int j = 0; j < message.length; j++){
                    sig.addByteToVerify(message[j]);
                }
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    @SuppressWarnings("null")
    public void testAddByteToVerifyNullInput() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            Byte b = null;
            try{
                sig.addByteToVerify(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddByteToVerifyUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addByteToVerify(message[0]);
    }

    @Test
    public void testAddBytesToVerifyByteArrayArray() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                sig.addBytesToVerify(message);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayArrayNullMatrixInput(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[][] b = null;
            try{
                sig.addBytesToVerify(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayArrayNullMatrixElement(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[][] b = {message, null};
            try{
                sig.addBytesToVerify(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToVerifyByteArrayArrayUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToVerify(message);
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntInt() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

                sig.addBytesToVerify(message, 0, message.length);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntNullInput(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[] b = null;
            try{
                sig.addBytesToVerify(b, 0, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntOffsetOutOfBounds(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            try{
                sig.addBytesToVerify(message, -3, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected ArrayIndexOutOfBoundsException");
            } catch (ArrayIndexOutOfBoundsException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntLengthOutOfBounds(){
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = null;
            try {
                sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            try{
                sig.addBytesToVerify(message, 0, message.length+3);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToVerifyByteArrayIntIntUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToVerify(message, 0, message.length);
    }

    @Test
    public void testAddBytesToVerifyByteBuffer() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
                ByteBuffer byteBuffer = ByteBuffer.wrap(message);

                sig.addBytesToVerify(byteBuffer);
                assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test
    public void testAddBytesToVerifyByteBufferNullInput() {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
                ByteBuffer byteBuffer = null;

                try{
                    sig.addBytesToVerify(byteBuffer);
                    fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
                } catch (NullPointerException e) {}
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToVerifyByteBufferUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToVerify(ByteBuffer.wrap(message));
    }

    @Test
    public void testSignByteArrayArray() {
        for(SigType type: types){
            CryptSignature sign = new CryptSignature(type);
            assertNotNull("SigType: "+type.name(), sign.sign(message));
        }
    }

    @Test
    public void testSignByteArrayArrayLength() {
        for(SigType type: ecdsaTypes){
            CryptSignature sign = new CryptSignature(type);
            assertTrue("SigType: "+type.name(), sign.sign(message).length <= type.maxSigSize);
        }
    }

    @Test
    public void testSignByteArrayArrayNullMatrixInput(){
        for(int i = 0; i < types.length; i++){
            CryptSignature sig = null;
            try {
                if(types[i].equals(dsaType)){
                    sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
                }
                else{
                    sig = new CryptSignature(types[i], keyPairs[i-1]);
                }
            } catch (InvalidKeyException e) {
                fail("InvalidKeyException thrown");
            }
            byte[][] b = null;
            try{
                sig.sign(b);
                fail("SigType: "+types[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testSignByteArrayArrayNullMatrixElement(){
        for(int i = 0; i < types.length; i++){
            CryptSignature sig = null;
            try {
                if(types[i].equals(dsaType)){
                    sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
                }
                else{
                    sig = new CryptSignature(types[i], keyPairs[i-1]);
                }
            } catch (InvalidKeyException e) {
                fail("SigType: "+types[i].name()+"InvalidKeyException thrown");
            }
            byte[][] b = {message, null};
            try{
                sig.sign(b);
                fail("SigType: "+types[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testSignByteArrayArrayVerifyMode() {
        for(int i = 0; i < types.length; i++){
            try {
                CryptSignature sig = null;
                if(types[i].equals(dsaType)){
                    sig = new CryptSignature(dsaPublicKey);
                }
                else{
                    sig = new CryptSignature(types[i], publicKeys[i-1]);
                }
                sig.sign(message);
                fail("SigType: "+types[i].name()+"Expected IllegalStateException");
            } catch (InvalidKeyException e) {
                fail("SigType: "+types[i].name()+"InvalidKeyException thrown");
            } catch (CryptFormatException e) {
                fail("SigType: "+types[i].name()+"CryptFormatException thrown");
            } catch (IllegalStateException e){} 
        }
    }

    @Test
    public void testSignToDSASignatureByteArrayArray() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature dsaSig = sig.signToDSASignature(message);
        assertNotNull(dsaSig);
        assertTrue(sig.verify(dsaSig, message));
    }

    @Test (expected = NullPointerException.class)
    public void testSignToDSASignatureByteArrayArrayNullMatrixInput() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        byte[][] b = null;
        sig.signToDSASignature(b);
    }

    @Test (expected = NullPointerException.class)
    public void testSignToDSASignatureByteArrayArrayNullMatrixElement() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        byte[][] b = {message, null};
        sig.signToDSASignature(b);
    }

    @Test (expected = IllegalStateException.class)
    public void testSignToDSASignatureByteArrayArrayVerifyMode() {
        CryptSignature sig = new CryptSignature(dsaPublicKey);
        sig.signToDSASignature(message);
    }

    @Test (expected = UnsupportedTypeException.class)
    public void  testSignToDSASignatureByteArrayArrayUnsupportedType() {
        CryptSignature sig = null;
        try {
            sig = new CryptSignature(ecdsaTypes[0], keyPairs[0]);
        } catch (InvalidKeyException e) {
            fail("InvalidKeyException thrown");
        }
        sig.signToDSASignature(message);
    }

    @Test
    public void testSignToDSASignatureBigInteger() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature dsaSig = sig.signToDSASignature(messageBigInteger);
        assertNotNull(dsaSig);
        assertTrue(sig.verify(dsaSig, messageBigInteger));
    }

    @Test (expected = NullPointerException.class)
    public void testSignToDSASignatureBigIntegerNullInput() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        BigInteger b = null;
        sig.signToDSASignature(b);
    }

    @Test (expected = IllegalStateException.class)
    public void testSignToDSASignatureBigIntegerVerifyMode() {
        CryptSignature sig = new CryptSignature(dsaPublicKey);
        sig.signToDSASignature(messageBigInteger);
    }

    @Test (expected = UnsupportedTypeException.class)
    public void  testSignToDSASignatureBigIntegerUnsupportedType() {
        CryptSignature sig = null;
        try {
            sig = new CryptSignature(ecdsaTypes[0], keyPairs[0]);
        } catch (InvalidKeyException e) {
            fail("InvalidKeyException thrown");
        }
        sig.signToDSASignature(messageBigInteger);
    }

    @Test
    public void testSignToNetworkFormat() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyByteArrayIntInt() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyByteArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyByteArrayByteArrayArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyDSASignatureBigInteger() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyBigIntegerBigIntegerBigInteger() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyDSASignatureByteArrayArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testVerifyBigIntegerBigIntegerByteArrayArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testGetPublicKey() {
        fail("Not yet implemented");
    }

    @Test
    public void testAsFieldSet() {
        fail("Not yet implemented");
    }

}
