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

import freenet.node.FSParseException;
import freenet.node.NodeStarter;
import freenet.support.Base64;
import freenet.support.IllegalBase64Exception;
import freenet.support.SimpleFieldSet;

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
    
    private static final byte[] trueDSASig = Hex.decode("3b715e0ff93e6690bbbbbac69cd11d178390f52805"
            + "209dbbada458f2aa6813257a0c3d99fca812adbbfc2891ff9d7ca4c84a0228a2cd6abe430f6a7d9a585b"
            + "77");
    
//    private static final byte[][] trueSigs = 
//        { Hex.decode("304502201083cce131fb0ef1a0b70b01133a466ca6923aeaaa07bd666a04c843057d18f30"
//                + "22100c0e7b7665e27a048c046595a7e152de963493cd191b24103b6b8d785d9e0b2d2"),
//        Hex.decode("30640230249a4eb939fff56d167e5e505951b58edd8cbf139b0798f91984569a2f608f57771c27a"
//                + "51c1e2eef5028708ec2a3261f0230230d702e0e1110c990cd6b58ee3bf32831b0b2c2651d2e34e3f"
//                + "a8077720553fc71cd0594861bfa5808509815c0886d60"),
//        Hex.decode("3081880242011f0c29428f3e3fbe86f98fa9170c0e9655a91839037005f935ebf4eaba76b9af729"
//                + "3923091f1f73147c7c76d385de36bac7e9f7a9dd3b211e8a916ecad42bda6770242018eb818d47f0"
//                + "b4bfa47baee04141528257b09fecc53542fad2ab6669449cb25c59d33d7e4fde6ba66243f6d59614"
//                + "ce6f3941bfb113eac3606d8802446644fb3e854")
//        };
    
    private static final byte[] falseDSASig = Hex.decode("b6669449cb25c59d33d7e4fde6ba66243f6d59614"
            + "209d3923091f1f73147c7c76d385de36bac7e9f7a9dd3b211e8a916ecad42bda6770242018eb818d47f0"
            + "774");
    
    private static final byte[][] falseECDSASigs = 
        { Hex.decode("640230249a4eb939fff56d167e5e505951b58edd8cbf139b0798f91984569a2f608f57771"
                    + "a8077720553fc71cd0594861bfa5808509815c0886d6091b24103b6b8d785d9e0b2d2"),
        Hex.decode("22100c0e7b7665e27a048c046595a7e152de963493cd191b24103b6b8d785d9e0b2d28f3071c27a"
                + "530640230249a4eb939fff56d167e5e505951b58edd8cbf139b0798f91984569a2f608f57771c27a"
                + "a8077720553fc71cd0594861bfa5808509815c0886d60"),
        Hex.decode("3081880242011f0c29428f3e3fbe86f98fa9170c0e9655a91839037005f935ebf4eaba76b9af729"
                + "530640230249a4eb939fff56d167e5e505951b58edd8cbf139b0798f91984569a2f608f57771c27a"
                + "b22100c0e7b7665e27a048c046595a7e152de963493cd191b24103b6b8d785d9e0b2d28f3071c27a"
                + "a8077720553fc71cd0594861bfa5808509815c0")
         };
    
    private static final byte[][] falseSigs = {falseDSASig, falseECDSASigs[0], falseECDSASigs[1],
        falseECDSASigs[2] };

    private static KeyPair[] keyPairs = new KeyPair[3];

    private static final byte[] message = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710");
    private static final ByteBuffer bufMessage = ByteBuffer.wrap(message);
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
    public void testAddByteToSign() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            for (int j = 0; j < message.length; j++){
                sig.addByteToSign(message[j]);
            }
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verifyData(sig.sign(), bufMessage));
        }
    }

    @Test
    public void testAddByteToSignVerifyMode() throws InvalidKeyException, CryptFormatException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addByteToSign(message[0]);
                fail("Expected IllegalStateException");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    @SuppressWarnings("null")
    public void testAddByteToSignNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToSignByteArrayArray() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            sig.addBytesToSign(message);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verifyData(sig.sign(), bufMessage));
        }
    }

    @Test
    public void testAddBytesToSignByteArrayArrayNullMatrixInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[][] b = null;
            try{
                sig.addBytesToSign(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayArrayNullMatrixElement() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToSignByteArrayArrayVerifyMode() 
            throws InvalidKeyException, CryptFormatException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(message);
                fail("Expected IllegalStateException");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntInt() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            sig.addBytesToSign(message, 0, message.length);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verifyData(sig.sign(), bufMessage));
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntNullInput() throws InvalidKeyException{
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] b = null;
            try{
                sig.addBytesToSign(b, 0, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntOffsetOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            try{
                sig.addBytesToSign(message, -3, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected ArrayIndexOutOfBoundsException");
            } catch (ArrayIndexOutOfBoundsException e) {}
        }
    }

    @Test
    public void testAddBytesToSignByteArrayIntIntLengthOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToSignByteArrayIntIntVerifyMode() 
            throws InvalidKeyException, CryptFormatException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(message, 0, message.length);
                fail("Expected IllegalStateException");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddBytesToSignByteBuffer() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            sig.addBytesToSign(bufMessage);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verifyData(sig.sign(), bufMessage));
        }
    }

    @Test
    public void testAddBytesToSignByteBufferNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer byteBuffer = null;

            try{
                sig.addBytesToSign(byteBuffer);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testAddBytesToSignByteBufferUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.addBytesToSign(ByteBuffer.wrap(message));
    }

    @Test
    public void testAddBytesToSignByteBufferVerifyMode() 
            throws InvalidKeyException, CryptFormatException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            try {
                CryptSignature sig = new CryptSignature(ecdsaTypes[i], publicKeys[i]);
                sig.addBytesToSign(ByteBuffer.wrap(message));
                fail("Expected IllegalStateException");
            } catch (IllegalStateException e){}
        }
    }

    @Test
    public void testAddByteToVerify() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            for (int j = 0; j < message.length; j++){
                sig.addByteToVerify(message[j]);
            }
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
        }
    }

    @Test
    @SuppressWarnings("null")
    public void testAddByteToVerifyNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToVerifyByteArrayArray() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            sig.addBytesToVerify(message);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayArrayNullMatrixInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[][] b = null;
            try{
                sig.addBytesToVerify(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayArrayNullMatrixElement() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToVerifyByteArrayIntInt() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);

            sig.addBytesToVerify(message, 0, message.length);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] b = null;
            try{
                sig.addBytesToVerify(b, 0, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntOffsetOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            try{
                sig.addBytesToVerify(message, -3, message.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected ArrayIndexOutOfBoundsException");
            } catch (ArrayIndexOutOfBoundsException e) {}
        }
    }

    @Test
    public void testAddBytesToVerifyByteArrayIntIntLengthOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
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
    public void testAddBytesToVerifyByteBuffer() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer byteBuffer = ByteBuffer.wrap(message);

            sig.addBytesToVerify(byteBuffer);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(sig.sign(message)));
        }
    }

    @Test
    public void testAddBytesToVerifyByteBufferNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer byteBuffer = null;

            try{
                sig.addBytesToVerify(byteBuffer);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
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
            assertTrue("SigType: "+type.name(), sign.sign(message).array().length <= type.maxSigSize);
        }
    }

    @Test
    public void testSignByteArrayArrayNullMatrixInput() throws InvalidKeyException{
        for(int i = 0; i < types.length; i++){
            CryptSignature sig = null;
            if(types[i].equals(dsaType)){
                sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sig = new CryptSignature(types[i], keyPairs[i-1]);
            }
            byte[][] b = null;
            try{
                sig.sign(b);
                fail("SigType: "+types[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testSignByteArrayArrayNullMatrixElement() throws InvalidKeyException{
        for(int i = 0; i < types.length; i++){
            CryptSignature sig = null;
            if(types[i].equals(dsaType)){
                sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sig = new CryptSignature(types[i], keyPairs[i-1]);
            }
            byte[][] b = {message, null};
            try{
                sig.sign(b);
                fail("SigType: "+types[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testSignByteArrayArrayVerifyMode() 
            throws InvalidKeyException, CryptFormatException {
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
            } catch (IllegalStateException e){} 
        }
    }

    @Test
    public void testSignToDSASignatureByteArrayArray() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature dsaSig = sig.signToDSASignature(message);
        assertNotNull(dsaSig);
        assertTrue(sig.verifyData(dsaSig, message));
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
    public void  testSignToDSASignatureByteArrayArrayUnsupportedType() throws InvalidKeyException {
        CryptSignature sig = null;
        sig = new CryptSignature(ecdsaTypes[0], keyPairs[0]);
        sig.signToDSASignature(message);
    }

    @Test
    public void testSignToDSASignatureBigInteger() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature dsaSig = sig.signToDSASignature(messageBigInteger);
        assertNotNull(dsaSig);
        assertTrue(sig.verifyData(dsaSig, messageBigInteger));
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
    public void  testSignToDSASignatureBigIntegerUnsupportedType() throws InvalidKeyException {
        CryptSignature sig = new CryptSignature(ecdsaTypes[0], keyPairs[0]);
        sig.signToDSASignature(messageBigInteger);
    }

    @Test
    public void testSignToNetworkFormat() throws InvalidKeyException {
        for(SigType type: ecdsaTypes){
            CryptSignature sign = new CryptSignature(type);
            byte[] sig = sign.signToNetworkFormat(message);
            assertEquals("SigType: "+type.name(), sig.length, type.maxSigSize);
            assertNotNull("SigType: "+type.name(), sig);
        }
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testSignToNetworkFormatUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.signToNetworkFormat(message);
    }
    
    @Test
    public void testSignToNetworkFormatNullMatrixInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[][] b = null;
            try{
                sig.signToNetworkFormat(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testSignToNetworkFormatNullMatrixElement() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[][] b = {message, null};
            try{
                sig.signToNetworkFormat(b);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testVerifyByteArray() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer signature = sig.sign(message);
            sig.addBytesToVerify(message);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(signature.array()));
        }
    }
    
    @Test
    public void testVerifyByteArrayFalseSig() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            sig.addBytesToVerify(message);
            assertFalse("SigType: "+ecdsaTypes[i].name(), sig.verify(falseSigs[i]));
        }
    }

    @Test
    public void testVerifyByteArrayNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] nullSig = null;
            sig.addBytesToVerify(message);
            try{
                sig.verify(nullSig);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyByteArrayUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.verify(trueDSASig);
    }

    @Test
    public void testVerifyByteBuffer() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer signature = sig.sign(message);
            sig.addBytesToVerify(message);
            assertTrue("SigType: "+ecdsaTypes[i].name(), sig.verify(signature));
        }
    }
    
    @Test
    public void testVerifyByteBufferFalseSig() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            sig.addBytesToVerify(message);
            assertFalse("SigType: "+ecdsaTypes[i].name(), 
                    sig.verify(ByteBuffer.wrap(falseSigs[i])));
        }
    }
    
    @Test
    public void testVerifyByteBufferNullInput() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            ByteBuffer nullSig = null;
            sig.addBytesToVerify(message);
            try{
                sig.verify(nullSig);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyByteBufferUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.verify(ByteBuffer.wrap(trueDSASig));
    }

    @Test
    public void testVerifyByteArrayIntInt() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] signature = sig.sign(message).array();
            sig.addBytesToVerify(message);
            assertTrue("SigType: "+ecdsaTypes[i].name(), 
                    sig.verify(signature, 0, signature.length));
        }
    }

    @Test
    public void testVerifyByteArrayIntIntFalseSig() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] signature = sig.sign(message).array();
            sig.addBytesToVerify(message);
            assertFalse("SigType: "+ecdsaTypes[i].name(), 
                    sig.verify(signature, 0, signature.length-30));
        }
    }
    
    @Test
    public void testVerifyByteArrayIntIntNullInput1() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] signature = null;
            sig.addBytesToVerify(message);
            try{
                sig.verify(signature, 0, 20);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }
    
    @Test
    public void testVerifyByteArrayIntIntOffsetOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] signature = sig.sign(message).array();
            sig.addBytesToVerify(message);
            try{
                sig.verify(signature, -1, signature.length);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }
    
    @Test
    public void testVerifyByteArrayIntIntLengthOutOfBounds() throws InvalidKeyException {
        for(int i = 0; i < ecdsaTypes.length; i++){
            CryptSignature sig = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
            byte[] signature = sig.sign(message).array();
            sig.addBytesToVerify(message);
            try{
                sig.verify(signature, 0, signature.length+6);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {}
        }
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyByteArrayIntIntUnsupportedType() {
        CryptSignature sig = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        sig.verify(trueDSASig, 0, trueDSASig.length);
    }

    @Test
    public void testVerifyByteArrayByteArrayArray() throws InvalidKeyException {
      for(int i = 0; i < types.length; i++){
          CryptSignature sign;
          if(types[i] == dsaType){
              sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
          }
          else{
              sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
          }
          byte[] sig = sign.sign(message).array();
          assertTrue("SigType: "+types[i].name(), sign.verifyData(sig, message));
      }
    }

    @Test
    public void testVerifyByteArrayByteArrayArrayFalseSig() throws InvalidKeyException {
      for(int i = 0; i < types.length; i++){
          CryptSignature sign;
          if(types[i] == dsaType){
              sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
          }
          else{
              sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
          }
          assertFalse("SigType: "+types[i].name(), sign.verifyData(falseSigs[i], message));
      }
    }
    
    @Test
    public void testVerifyByteArrayByteArrayArrayNullInput1() throws InvalidKeyException {
        for(int i = 0; i < types.length; i++){
            CryptSignature sign;
            if(types[i] == dsaType){
                sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
            }
            byte[] signature = null;
            try{
                sign.verifyData(signature, message);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test
    public void testVerifyByteArrayByteArrayArrayNullMatrix() throws InvalidKeyException {
        for(int i = 0; i < types.length; i++){
            CryptSignature sign;
            if(types[i] == dsaType){
                sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
            }
            byte[] sig = sign.sign(message).array();
            byte[][] nullInput = null;
            try{
                sign.verifyData(sig, nullInput);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test
    public void testVerifyByteArrayByteArrayArrayNullMatrixElement() throws InvalidKeyException {
        for(int i = 0; i < types.length; i++){
            CryptSignature sign;
            if(types[i] == dsaType){
                sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
            }
            byte[] sig = sign.sign(message).array();
            byte[][] nullInput = {message, null};
            try{
                sign.verifyData(sig, nullInput);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test
    public void testVerifyByteBufferByteBuffer() throws InvalidKeyException {
      for(int i = 0; i < types.length; i++){
          CryptSignature sign;
          if(types[i] == dsaType){
              sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
          }
          else{
              sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
          }
          ByteBuffer sig = sign.sign(message);
          assertTrue("SigType: "+types[i].name(), sign.verifyData(sig, bufMessage));
      }
    }

    @Test
    public void testVerifyByteBufferByteBufferFalseSig() throws InvalidKeyException {
      for(int i = 0; i < types.length; i++){
          CryptSignature sign;
          if(types[i] == dsaType){
              sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
          }
          else{
              sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
          }
          assertFalse("SigType: "+types[i].name(), 
                  sign.verifyData(ByteBuffer.wrap(falseSigs[i]), bufMessage));
      }
    }
    
    @Test
    public void testVerifyByteBufferByteBufferNullInput1() throws InvalidKeyException {
        for(int i = 0; i < types.length; i++){
            CryptSignature sign;
            if(types[i] == dsaType){
                sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
            }
            ByteBuffer signature = null;
            try{
                sign.verifyData(signature, bufMessage);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }
    
    @Test
    public void testVerifyByteArrayByteArrayArrayNullInput2() throws InvalidKeyException {
        for(int i = 0; i < types.length; i++){
            CryptSignature sign;
            if(types[i] == dsaType){
                sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
            }
            else{
                sign = new CryptSignature(ecdsaTypes[i-1], keyPairs[i-1]);
            }
            ByteBuffer sig = sign.sign(message);
            ByteBuffer nullInput = null;
            try{
                sign.verifyData(sig, nullInput);
                fail("SigType: "+ecdsaTypes[i].name()+"Expected NullPointerException");
            } catch (NullPointerException e) {}
        }
    }

    @Test
    public void testVerifyDSASignatureBigInteger() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        assertTrue(sign.verifyData(sig, messageBigInteger));
    }

    @Test
    public void testVerifyDSASignatureBigIntegerFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        assertFalse(sign.verifyData(sig, messageBigInteger));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureBigIntegerNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = null;
        sign.verifyData(sig, messageBigInteger);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureBigIntegerNullInput2() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger nullInput = null;
        sign.verifyData(sig, nullInput);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyDSASignatureBigIntegerUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        sign.verifyData(sig, messageBigInteger);
    }

    @Test
    public void testVerifyBigIntegerBigIntegerBigInteger() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        assertTrue(sign.verifyData(r, s, messageBigInteger));
    }

    @Test
    public void testVerifyBigIntegerBigIntegerBigIntegerFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        assertFalse(sign.verifyData(messageBigInteger, messageBigInteger, messageBigInteger));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerBigIntegerNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger r = null;
        BigInteger s = sig.getS();
        sign.verifyData(r, s, messageBigInteger);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerBigIntegerNullInput2() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = null;
        sign.verifyData(r, s, messageBigInteger);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerBigIntegerNullInput3() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        BigInteger m = null;
        sign.verifyData(r, s, m);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyBigIntegerBigIntegerBigIntegerUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        sign.verifyData(r, s, messageBigInteger);
    }

    @Test
    public void testVerifyDSASignatureByteArrayArray() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        assertTrue(sign.verifyData(sig, message));
    }

    @Test
    public void testVerifyDSASignatureByteArrayArrayFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        assertFalse(sign.verifyData(sig, message));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureByteArrayArrayNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = null;
        sign.verifyData(sig, message);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureByteArrayArrayNullMatrix() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        byte[][] nullInput = null;
        sign.verifyData(sig, nullInput);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureByteArrayArrayNullMatrixElement() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        byte[][] nullInput = {message, null};
        sign.verifyData(sig, nullInput);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyDSASignatureByteArrayArrayUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        sign.verifyData(sig, message);
    }
    
    @Test
    public void testVerifyDSASignatureByteBuffer() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(bufMessage);
        assertTrue(sign.verifyData(sig, bufMessage));
    }

    @Test
    public void testVerifyDSASignatureByteBufferFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        assertFalse(sign.verifyData(sig, bufMessage));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureByteBufferNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = null;
        sign.verifyData(sig, bufMessage);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyDSASignatureByteBufferNullInput2() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        ByteBuffer nullInput = null;
        sign.verifyData(sig, nullInput);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyDSASignatureByteBufferUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        sign.verifyData(sig, bufMessage);
    }

    @Test
    public void testVerifyBigIntegerBigIntegerByteArrayArray() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        assertTrue(sign.verifyData(r, s, message));
    }

    @Test
    public void testVerifyBigIntegerBigIntegerByteArrayArrayFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        assertFalse(sign.verifyData(messageBigInteger, messageBigInteger, message));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteArrayArrayNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(messageBigInteger);
        BigInteger r = null;
        BigInteger s = sig.getS();
        sign.verifyData(r, s, message);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteArrayArrayNullInput2() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = null;
        sign.verifyData(r, s, message);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteArrayArrayNullMatrix() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        byte[][] m = null;
        sign.verifyData(r, s, m);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteArrayArrayNullMatrixElement() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        byte[][] m = {message, null};
        sign.verifyData(r, s, m);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyBigIntegerBigIntegerByteArrayArrayUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        sign.verifyData(r, s, message);
    }

    @Test
    public void testVerifyBigIntegerBigIntegerByteBuffer() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        assertTrue(sign.verifyData(r, s, bufMessage));
    }

    @Test
    public void testVerifyBigIntegerBigIntegerByteBufferFalseSig() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        assertFalse(sign.verifyData(messageBigInteger, messageBigInteger, bufMessage));
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteBufferNullInput1() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = null;
        BigInteger s = sig.getS();
        sign.verifyData(r, s, bufMessage);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteBufferNullInput2() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = null;
        sign.verifyData(r, s, bufMessage);
    }
    
    @Test (expected = NullPointerException.class)
    public void testVerifyBigIntegerBigIntegerByteBufferNullInput3() {
        CryptSignature sign = new CryptSignature(dsaPublicKey, dsaPrivateKey);
        DSASignature sig = sign.signToDSASignature(message);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        ByteBuffer m = null;
        sign.verifyData(r, s, m);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testVerifyBigIntegerBigIntegerByteBufferUnsupportedType() throws InvalidKeyException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], keyPairs[1]);
        DSASignature sig = dsaType.get(messageBigInteger, messageBigInteger);
        BigInteger r = sig.getR();
        BigInteger s = sig.getS();
        sign.verifyData(r, s, bufMessage);
    }

    @Test
    public void testGetPublicKey() throws InvalidKeyException, CryptFormatException {
        CryptSignature sign = new CryptSignature(ecdsaTypes[1], publicKeys[1]);
        assertArrayEquals(sign.getPublicKey().getEncoded(), publicKeys[1]);
    }
    
    @Test (expected = UnsupportedTypeException.class)
    public void testGetPublicKeyUnsupportedType() throws InvalidKeyException, CryptFormatException {
        CryptSignature sign = new CryptSignature(dsaPublicKey);
        sign.getPublicKey();
    }

    @Test
    public void testAsFieldSetBothKeys() throws IllegalBase64Exception, FSParseException, InvalidKeyException {
    	for(int i = 0; i < ecdsaTypes.length; i++){
    		CryptSignature sign = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
    		SimpleFieldSet sfs = sign.asFieldSet(true);
    		SimpleFieldSet isfs = sfs.getSubset(ecdsaTypes[i].name());
    		byte[] pub = Base64.decode(isfs.get("pub"));
    		byte[] pri = Base64.decode(isfs.get("pri"));
    		assertArrayEquals("SigType: "+ecdsaTypes[i].name(), pub, keyPairs[i].getPublic().getEncoded());
    		assertArrayEquals("SigType: "+ecdsaTypes[i].name(), pri, keyPairs[i].getPrivate().getEncoded());
    	}
    }

    @Test
    public void testAsFieldSetPublicKey() throws InvalidKeyException, IllegalBase64Exception, FSParseException {
    	for(int i = 0; i < ecdsaTypes.length; i++){
    		CryptSignature sign = new CryptSignature(ecdsaTypes[i], keyPairs[i]);
    		SimpleFieldSet sfs = sign.asFieldSet(false);
    		SimpleFieldSet isfs = sfs.getSubset(ecdsaTypes[i].name());
    		byte[] pub = Base64.decode(isfs.get("pub"));
    		try{
    			byte[] pri = Base64.decode(isfs.get("pri"));
    			fail("Expected NullPointerException");
    		} catch(NullPointerException e){}
    		assertArrayEquals("SigType: "+ecdsaTypes[i].name(), pub, keyPairs[i].getPublic().getEncoded());
    	}
    }

}
