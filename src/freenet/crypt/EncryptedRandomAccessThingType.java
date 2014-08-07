package freenet.crypt;

import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;

public enum EncryptedRandomAccessThingType {
    ChaCha128(1, CryptBitSetType.ChaCha128, MACType.Poly1305AES, 8),
    ChaCha256(2, CryptBitSetType.ChaCha256, MACType.Poly1305AES, 8);

    public final int bitmask;
    public final CryptBitSetType encryptType;
    public final KeyType encryptKey;
    public final MACType macType;
    public final KeyType macKey;
    public final int skippingCipherIVLen;//bytes

    private EncryptedRandomAccessThingType(int bitmask, CryptBitSetType type, MACType macType, 
            int ivLen){
        this.bitmask = bitmask;
        this.encryptType = type;
        this.encryptKey = type.keyType;
        this.macType = macType;
        this.macKey = macType.keyType;
        this.skippingCipherIVLen = ivLen;
    }

    public final SkippingStreamCipher get(){
        return new ChaChaEngine();
    }

}
