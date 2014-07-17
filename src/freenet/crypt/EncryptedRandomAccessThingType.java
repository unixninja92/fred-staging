package freenet.crypt;

import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;

public enum EncryptedRandomAccessThingType {
	ChaCha128("CHACHA", KeyType.ChaCha128),
	ChaCha256("CHACHA", KeyType.ChaCha256);
	
	public final String alg;
	public final KeyType keyType;
	
	private EncryptedRandomAccessThingType(String alg, KeyType type){
		this.alg = alg;
		this.keyType = type;
	}
	
	public final SkippingStreamCipher get(){
		return new ChaChaEngine();
	}

}
