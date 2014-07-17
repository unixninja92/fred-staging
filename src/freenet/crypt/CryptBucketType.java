/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;

public enum CryptBucketType {
	@Deprecated
	AEADAESOCBDraft00(1, KeyType.AES128, 16),
	AEADAESOCB(2, KeyType.AES128, 15);
	
	public final int bitmask;
	public final KeyType keyType;
	public final int blockSize;
	public final int nonceSize;
	
	private CryptBucketType(int bitmask, KeyType keyType, int nonceSize){
		this.bitmask = bitmask;
		this.keyType = keyType;
		this.blockSize = 128;
		this.nonceSize = nonceSize;
	}
	
	@SuppressWarnings("deprecation")
	public final AEADBlockCipher getBlockCipher(){
		BlockCipher hashCipher = new AESLightEngine();
		BlockCipher mainCipher = new AESFastEngine();
		if(nonceSize == 16){
			return new OCBBlockCipher_v149(hashCipher, mainCipher);
		}
		else{
			return new OCBBlockCipher(hashCipher, mainCipher);
		}
	}
	
}
