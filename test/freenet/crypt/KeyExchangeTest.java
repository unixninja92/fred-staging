package freenet.crypt;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;

import org.junit.Test;

public class KeyExchangeTest {
    private static final KeyExchType[] types = KeyExchType.values();

    @Test
    public void testGetPublicKeyNetworkFormat() {
        for(KeyExchType type: types) {
            KeyExchange exch = new KeyExchange(type);
            assertEquals("KeyExchType: "+type, exch.getPublicKeyNetworkFormat().length, 
                    type.modulusSize);
        }
    }

    @Test
    public void testGetHMACKey() throws InvalidKeyException {
        for(KeyExchType type: types) {
            KeyExchange exchA = new KeyExchange(type);
            KeyExchange exchB = new KeyExchange(type);
            ByteBuffer secretA = exchA.getHMACKey(exchB.getPublicKey());
            ByteBuffer secretB = exchB.getHMACKey(exchA.getPublicKey());
            assertTrue("KeyExchType: "+type, secretA.equals(secretB));
        }
    }

    @Test 
    public void testGetHMACKeyNullInput() {
        for(KeyExchType type: types) {
            KeyExchange exch = new KeyExchange(type);
            ECPublicKey key = null;
            try{
                ByteBuffer secret = exch.getHMACKey(key);
                fail("Expected NullPointerException");
            } catch(InvalidKeyException e) {}
        }
    }

}
