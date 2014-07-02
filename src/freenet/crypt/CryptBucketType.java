/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CryptBucketType {
//	RijndaelECB(1, "Rijndael", 256),
//	RigndaelECB(2, "Rijndael", 256, 128),
//	RijndaelCTR(4, "Rijndael", 256),
//	RijndaelPCFB(8, "Rijndael", 256),
//	AESCTR(16, "AES", "AES/CTR/NOPADDING", KeyType.AES256),
	AEADAESOCBDraft00(32, "AES", KeyType.AES128),
	AEADAESOCB(64, "AES", KeyType.AES128);
	
	public final int bitmask;
	public final int keySize;
	public final int blockSize;
	public final String algName;
	public final String cipherName;
	public final KeyType keyType;
	
//	CryptBucketType(int bitmask, String cipherName, int keySize){
//		this.bitmask = bitmask;
//		this.cipherName = cipherName;
//		this.keySize = keySize;
//		this.blockSize = keySize;
//		algName = name();
//		keyType = null;
//	}
	
	CryptBucketType(int bitmask, String cipherName, KeyType keyType){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keySize = keyType.keySize;
		this.blockSize = keySize;
		algName = name();
		this.keyType = keyType;
	}
	
//	CryptBucketType(int bitmask, String cipherName, int keySize, int blockSize){
//		this.bitmask = bitmask;
//		this.cipherName = cipherName;
//		this.keySize = keySize;
//		this.blockSize = blockSize;
//		algName = name();
//		keyType = null;
//	}
	
//	CryptBucketType(int bitmask, String cipherName, String algName, KeyType keyType){
//		this.bitmask = bitmask;
//		this.cipherName = cipherName;
//		this.keySize = keyType.keySize;
//		this.blockSize = keySize;
//		this.algName = algName;
//		this.keyType = keyType;
//	}
	
}
