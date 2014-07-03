/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;

public enum CryptBucketType {
	@Deprecated
	AEADAESOCBDraft00(32, "AES", KeyType.AES128, 16),
	AEADAESOCB(64, "AES", KeyType.AES128, 15);
	
	public final int bitmask;
	public final String cipherName;
	public final KeyType keyType;
	public final int nonceSize;
	
	CryptBucketType(int bitmask, String cipherName, KeyType keyType, int nonceSize){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keyType = keyType;
		this.nonceSize = nonceSize;
	}
	
	public AEADBlockCipher getBlockCipher(BlockCipher hashCipher, BlockCipher mainCipher){
		if(nonceSize == 16){
			return new OldOCBBlockCipher(hashCipher, mainCipher);
		}
		else{
			return new OCBBlockCipher(hashCipher, mainCipher);
		}
	}
	
}
