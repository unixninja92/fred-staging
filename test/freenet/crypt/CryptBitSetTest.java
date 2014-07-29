package freenet.crypt;

import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.BitSet;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class CryptBitSetTest {
    private static final CryptBitSetType[] cipherTypes = CryptBitSetType.values();

    private static final byte[] ivPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710");

    private static final byte[][] plainText =
        { Hex.decode("0123456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef"),
        Hex.decode("0123456789abcdef1123456789abcdef"), 
        ivPlainText, ivPlainText, ivPlainText, ivPlainText};

    private static final byte[][] keys = 
        { Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
        Hex.decode("deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567"),
        Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        Hex.decode("8c123cffb0297a71ae8388109a6527dd"),
        Hex.decode("a63add96a3d5975e2dad2f904ff584a32920e8aa54263254161362d1fb785790")};
    private static final byte[][] ivs = 
        { null,
        null,
        Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        Hex.decode("73c3c8df749084bb"),
        Hex.decode("7b471cf26ee479fb")};

    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSuccessfulRoundTripByteArray() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }
                byte[] ciphertext = crypt.encrypt(plainText[i]);

                byte[] decipheredtext = crypt.decrypt(ciphertext);
                assertArrayEquals("CryptBitSetType: "+type.name(), plainText[i], decipheredtext);
            }

        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testSuccessfulRoundTripByteArrayReset() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }
                crypt.encrypt(plainText[i]);
                byte[] ciphertext = crypt.encrypt(plainText[i]);
                crypt.encrypt(plainText[i]);

                byte[] decipheredtext = crypt.decrypt(ciphertext);
                assertArrayEquals("CryptBitSetType: "+type.name(), plainText[i], decipheredtext);
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testSuccessfulRoundTripByteArrayNewInstance() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }
                crypt.encrypt(plainText[i]);
                byte[] ciphertext = crypt.encrypt(plainText[i]);
                crypt.encrypt(plainText[i]);

                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }
                byte[] decipheredtext = crypt.decrypt(ciphertext);
                assertArrayEquals("CryptBitSetType: "+type.name(), plainText[i], decipheredtext);
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testSuccessfulRoundTripBitSet() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }
                BitSet plaintext = BitSet.valueOf(plainText[i]);
                System.out.println(Hex.toHexString(plaintext.toByteArray()));
                BitSet ciphertext = crypt.encrypt(plaintext);
                BitSet decipheredtext = crypt.decrypt(ciphertext);
                System.out.println(Hex.toHexString(decipheredtext.toByteArray()));
                assertTrue("CryptBitSetType: "+type.name(), plaintext.equals(decipheredtext));
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testEncryptByteArrayNullInput(){
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                byte[] nullArray = null;
                try{
                    crypt.encrypt(nullArray);
                    fail("CryptBitSetType: "+type.name()+": Expected NullPointerException");
                }catch(NullPointerException e){}
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testEncryptBitSetNullInput(){
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                BitSet nullSet = null;
                try{
                    crypt.encrypt(nullSet);
                    fail("CryptBitSetType: "+type.name()+": Expected NullPointerException");
                }catch(NullPointerException e){}
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testEncryptByteArrayIntIntNullInput() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                byte[] nullArray = null;
                try{
                    crypt.encrypt(nullArray, 0, plainText[i].length);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or NullPointerException");
                }catch(IllegalArgumentException | NullPointerException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testEncryptByteArrayIntIntOffsetOutOfBounds() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                try{
                    crypt.encrypt(plainText[i], -3, plainText[i].length-3);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or ArrayIndexOutOfBoundsException");
                }catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testEncryptByteArrayIntIntLengthOutOfBounds() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                try{
                    crypt.encrypt(plainText[i], 0, plainText[i].length+3);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or ArrayIndexOutOfBoundsException");
                }catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testDecryptByteArrayNullInput(){
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                byte[] nullArray = null;
                try{
                    crypt.decrypt(nullArray);
                    fail("CryptBitSetType: "+type.name()+": Expected NullPointerException");
                }catch(NullPointerException e){}
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testDecryptBitSetNullInput(){
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                BitSet nullSet = null;
                try{
                    crypt.decrypt(nullSet);
                    fail("CryptBitSetType: "+type.name()+": Expected NullPointerException");
                }catch(NullPointerException e){}
            }
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testDecryptByteArrayIntIntNullInput() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                byte[] nullArray = null;
                try{
                    crypt.decrypt(nullArray, 0, plainText[i].length);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or NullPointerException");
                }catch(NullPointerException | IllegalArgumentException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testDecryptByteArrayIntIntOffsetOutOfBounds() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                try{
                    crypt.decrypt(plainText[i], -3, plainText[i].length-3);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or ArrayIndexOutOfBoundsException");
                }catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testDecryptByteArrayIntIntLengthOutOfBounds() {
        try{
            for(int i = 0; i < cipherTypes.length; i++){
                CryptBitSetType type = cipherTypes[i];
                CryptBitSet crypt;
                if(ivs[i] == null){
                    crypt = new CryptBitSet(type, keys[i]);
                } else {
                    crypt = new CryptBitSet(type, keys[i], ivs[i]);
                }

                try{
                    crypt.decrypt(plainText[i], 0, plainText[i].length+3);
                    fail("CryptBitSetType: "+type.name()+": Expected IllegalArgumentException or ArrayIndexOutOfBoundsException");
                }catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e){}
            } 
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testGetIV() {
        try{
            int i = 4;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
            assertArrayEquals(crypt.getIV().getIV(), ivs[i]);
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testSetIVIvParameterSpec() {
        try {
            int i = 4;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
            crypt.genIV();
            crypt.setIV(new IvParameterSpec(ivs[i]));
            assertArrayEquals(ivs[i], crypt.getIV().getIV());
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test 
    public void testSetIVIvParameterSpecNullInput() {
        IvParameterSpec nullInput = null;
        int i = 4;
        CryptBitSet crypt = null;
        try {
            crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            fail("GeneralSecurityException thrown");
        }
        try{
            crypt.setIV(nullInput);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e){}
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testSetIVIvParameterSpecUnsupportedTypeException() {
        try{
            int i = 0;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i]);
            crypt.setIV(new IvParameterSpec(ivs[4]));
            fail("Expected UnsupportedTypeException");
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testGenIV() {
        try{
            int i = 4;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
            assertNotNull(crypt.genIV());
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test
    public void testGenIVLength() {
        try{
            int i = 4;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i], ivs[i]);
            assertEquals(crypt.genIV().length, cipherTypes[i].ivSize);
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

    @Test (expected = UnsupportedTypeException.class)
    public void testGenIVUnsupportedTypeException() {
        try{
            int i = 1;
            CryptBitSet crypt = new CryptBitSet(cipherTypes[i], keys[i]);
            crypt.genIV();
            fail("Expected UnsupportedTypeException");
        } catch(GeneralSecurityException e){
            fail("GeneralSecurityException thrown");
        }
    }

}
