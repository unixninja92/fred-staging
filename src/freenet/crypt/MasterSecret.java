package freenet.crypt;

import java.io.Serializable;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;

public final class MasterSecret implements Serializable{
    private static final long serialVersionUID = -8411217325990445764L;
    private final SecretKey masterKey;
    private final MessageAuthCode kdf;
    
    public MasterSecret(){
        masterKey = KeyGenUtils.genSecretKey(KeyType.HMACSHA512);
        MessageAuthCode temp = null;
        try {
            temp = new MessageAuthCode(MACType.HMACSHA512, masterKey);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        kdf = temp;
    }
    
    public SecretKey deriveKey(KeyType type){
        return KeyGenUtils.getSecretKey(type, kdf.genMac(type.name().getBytes()).array());
    }
    
//    public static void save(){
//        MasterSecret key = new MasterSecret(CryptBitSetType.ChaCha256);
////        key.
//    }
}
