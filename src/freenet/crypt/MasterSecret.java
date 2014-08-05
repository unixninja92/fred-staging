package freenet.crypt;

import java.io.Serializable;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;

public final class MasterSecret implements Serializable{
    private static final long serialVersionUID = -8411217325990445764L;
    private KeyType type;
    private SecretKey masterKey;
    
    public MasterSecret(KeyType type){
        this.type = type;
        masterKey =  KeyGenUtils.genSecretKey(type);
    }
    
    public SecretKey deriveKey(Class<?> c, String kdfInput){
        try {
            return KeyGenUtils.getSecretKey(type, 
                    KeyGenUtils.deriveKey(masterKey, c, kdfInput).array());
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
