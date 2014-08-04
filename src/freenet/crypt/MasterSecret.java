package freenet.crypt;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.BitSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public final class MasterSecret implements Serializable{
    private static final long serialVersionUID = -8411217325990445764L;
    private CryptBitSetType masterKeyType;
    private SecretKey masterSecret;
    private CryptBitSet kdfKeyCrypt;
    
    public MasterSecret(CryptBitSetType type){
        this.masterKeyType = type;
        masterSecret = KeyGenUtils.genSecretKey(type.keyType);
        try {
            kdfKeyCrypt = new CryptBitSet(type, masterSecret);
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    public BitSet encryptKey(BitSet keyToEncrypt, IvParameterSpec iv) throws InvalidAlgorithmParameterException{
        kdfKeyCrypt.setIV(iv);
        return kdfKeyCrypt.encrypt(keyToEncrypt);
    }
    
    public BitSet decryptKey(BitSet keyToDecrypt, IvParameterSpec iv) throws InvalidAlgorithmParameterException{
        kdfKeyCrypt.setIV(iv);
        return kdfKeyCrypt.decrypt(keyToDecrypt);
    }
}
