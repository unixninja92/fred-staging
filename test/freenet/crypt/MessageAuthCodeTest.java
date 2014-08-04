package freenet.crypt;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class MessageAuthCodeTest{
    static private final MACType[] types = 
        { MACType.HMACSHA256, MACType.HMACSHA512, MACType.Poly1305AES};
    static private final byte[][] keys = 
        { Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), 
        Hex.decode("95cc0e44d0b79a8856afcae1bec4fe3c01bcb20bfc8b6e03609ddd09f44b060f")};
    static private final byte[][] messages = { "Hi There".getBytes(), new byte[128]};
    static private final IvParameterSpec[] IVs = 
        { null, new IvParameterSpec(new byte[16])};
    static private final byte[][] trueMacs = 
        { Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        Hex.decode("4bb5e21dd13001ed5faccfcfdaf8a854")};
    static private final byte[][] falseMacs = 
        { Hex.decode("4bb5e21dd13001ed5faccfcfdaf8a854881dc200c9833da726e9376c2e32cff7"),
        Hex.decode("881dc200c9833da726e9376c2e32cff7")};

    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testAddByte() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            for (int j = 0; j < messages[i].length; j++){
                mac.addByte(messages[i][j]);
            }
            assertArrayEquals("MACType: "+types[i].name(), mac.genMac(), trueMacs[i]);
        }
    }

    @Test
    @SuppressWarnings("null")
    public void testAddByteNullInput() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            boolean throwNull = false;
            Byte nullByte = null;
            try{
                mac.addByte(nullByte);
            }catch(NullPointerException e){
                throwNull = true;
            }

            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    public void testAddBytesByteBuffer() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            ByteBuffer byteBuffer = ByteBuffer.wrap(messages[i]);

            mac.addBytes(byteBuffer);
            assertArrayEquals("MACType: "+types[i].name(), mac.genMac(), trueMacs[i]);
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void testAddBytesByteBufferNullInput() throws InvalidKeyException {
        int i = 0;
        MessageAuthCode mac;
        mac = new MessageAuthCode(types[i], keys[i]);

        ByteBuffer byteBuffer = null;
        mac.addBytes(byteBuffer);
    }

    @Test
    public void testAddBytesByteArrayIntInt() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            mac.addBytes(messages[i], 0, messages[i].length/2);
            mac.addBytes(messages[i], messages[i].length/2, 
                    messages[i].length-messages[i].length/2);

            assertArrayEquals("MACType: "+types[i].name(), mac.genMac(), trueMacs[i]);
        }
    }

    @Test
    public void testAddBytesByteArrayIntIntNullInput() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            boolean throwNull = false;
            byte[] nullArray = null;
            try{
                mac.addBytes(nullArray, 0, messages[i].length);
            }catch(NullPointerException e){
                throwNull = true;
            }

            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    public void testAddBytesByteArrayIntIntOffsetOutOfBounds() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            boolean throwNull = false;
            try{
                mac.addBytes(messages[i], -3, messages[i].length-3);
            }catch(IllegalArgumentException e){
                throwNull = true;
            }

            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    public void testAddBytesByteArrayIntIntLengthOutOfBounds() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            } else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            boolean throwNull = false;
            try{
                mac.addBytes(messages[i], 0, messages[i].length+3);
            }catch(IllegalArgumentException e){
                throwNull = true;
            }

            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    //tests .genMac() and .addBytes(byte[]...] as well
    public void testGetMacByteArrayArray() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            byte[] result = mac.genMac(messages[i]);
            assertTrue("MACType: "+types[i].name(), MessageAuthCode.verify(result, trueMacs[i]));
        }
    }

    @Test
    public void testGetMacByteArrayArrayReset() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            mac.addBytes(messages[i]);
            byte[] result = mac.genMac(messages[i]);
            assertArrayEquals("MACType: "+types[i].name(), result, trueMacs[i]);
        }
    }

    @Test
    public void testGetMacByteArrayArrayNullInput() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }

            boolean throwNull = false;
            byte[] nullArray = null;
            try{
                mac.genMac(nullArray);
            }catch(NullPointerException e){
                throwNull = true;
            }

            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test (expected = NullPointerException.class)
    public void testGetMacByteArrayArrayNullMatrixElementInput() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        byte[][] nullMatrix = {messages[1], null};
        mac.genMac(nullMatrix);
    }

    @Test
    public void testVerify() {
        assertTrue(MessageAuthCode.verify(trueMacs[1], trueMacs[1]));
    }

    @Test
    public void testVerifyFalse() {
        assertFalse(MessageAuthCode.verify(trueMacs[1], falseMacs[1]));
    }

    @Test (expected = NullPointerException.class)
    public void testVerifyNullInput1() {
        byte[] nullArray = null;
        MessageAuthCode.verify(nullArray, trueMacs[1]);
    }

    @Test (expected = NullPointerException.class)
    public void testVerifyNullInput2() {
        byte[] nullArray = null;
        MessageAuthCode.verify(trueMacs[1], nullArray);
    }

    @Test
    public void testVerifyData() throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            assertTrue("MACType: "+types[i].name(), mac.verifyData(trueMacs[i], messages[i]));
        }
    }

    @Test
    public void testVerifyDataFalse() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            assertFalse("MACType: "+types[i].name(), mac.verifyData(falseMacs[i], messages[i]));
        }
    }

    @Test
    public void testVerifyDataNullInput1() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            boolean throwNull = false;
            byte[] nullArray = null;
            try{
                mac.verifyData(nullArray, messages[i]);
            }catch(NullPointerException e){
                throwNull = true;
            }
            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    public void testVerifyDataNullInput2() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            boolean throwNull = false;
            byte[] nullArray = null;
            try{
                mac.verifyData(trueMacs[i], nullArray);
            }catch(NullPointerException e){
                throwNull = true;
            }
            assertTrue("MACType: "+types[i].name(), throwNull);
        }
    }

    @Test
    public void testGetKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        for(int i = 0; i < types.length; i++){
            MessageAuthCode mac;
            if(types[i].ivlen != -1){
                mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
            }
            else{
                mac = new MessageAuthCode(types[i], keys[i]);
            }
            assertArrayEquals("MACType: "+types[i].name(), mac.getKey().getEncoded(), keys[i]);
        }
    }

    @Test
    public void testGetIV() throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        assertArrayEquals(mac.getIv().getIV(), IVs[1].getIV());
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGetIVUnsupportedTypeException() throws InvalidKeyException {
        MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
        mac.getIv();
    }

    @Test
    public void testSetIVIvParameterSpec() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        mac.genIv();
        mac.setIv(IVs[1]);
        assertArrayEquals(IVs[1].getIV(), mac.getIv().getIV());
    }

    @Test (expected = IllegalArgumentException.class)
    public void testSetIVIvParameterSpecNullInput() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec nullInput = null;
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        mac.setIv(nullInput);
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testSetIVIvParameterSpecUnsupportedTypeException() 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
        mac.setIv(IVs[1]);
    }

    @Test
    public void testGenIV() throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        assertNotNull(mac.genIv());
    }

    @Test
    public void testGenIVLength() throws InvalidKeyException, InvalidAlgorithmParameterException {
        MessageAuthCode mac = new MessageAuthCode(types[1], keys[1], IVs[1]);
        assertEquals(mac.genIv().getIV().length, types[1].ivlen);
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGenIVUnsupportedTypeException() throws InvalidKeyException {
        MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
        mac.genIv();
    }

}
