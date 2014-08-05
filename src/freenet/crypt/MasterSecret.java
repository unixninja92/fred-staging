package freenet.crypt;

import java.io.Serializable;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;

public final class MasterSecret implements Serializable{
    private static final long serialVersionUID = -8411217325990445764L;
    private final SecretKey masterKey;
    
    public MasterSecret(){
        masterKey = KeyGenUtils.genSecretKey(KeyType.HMACSHA512);
    }
    
    public SecretKey deriveKey(KeyType type){
        try {
            MessageAuthCode kdf = new MessageAuthCode(MACType.HMACSHA512, masterKey);
            return KeyGenUtils.getSecretKey(type, kdf.genMac(type.name().getBytes()).array());
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    
//    public static void save(){
//        MasterSecret key = new MasterSecret(CryptBitSetType.ChaCha256);
////        key.
//    }
}
