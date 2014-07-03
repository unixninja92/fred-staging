/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;


public enum CryptBitSetType {
	RijndaelECB(1, KeyType.Rijndael256),
	RijndaelECB128(2, KeyType.Rijndael256, 128),
	RijndaelCTR(4, KeyType.Rijndael256),
	RijndaelPCFB(8, KeyType.Rijndael256),
	AESCTR(16, "AES/CTR/NOPADDING", KeyType.AES256),
	ChaCha(32, KeyType.ChaCha);
	
	public final int bitmask;
	public final int blockSize;
	public final String algName;
	public final String cipherName;
	public final KeyType keyType;
	
	CryptBitSetType(int bitmask, KeyType keyType){
	this.bitmask = bitmask;
	this.keyType = keyType;
	this.cipherName = keyType.alg;
	this.blockSize = keyType.keySize;
	algName = name();
	}
	
	CryptBitSetType(int bitmask, KeyType keyType, int blockSize){
		this.bitmask = bitmask;
		this.keyType = keyType;
		this.cipherName = keyType.alg;
		this.blockSize = blockSize;
		algName = name();
	}
	
	CryptBitSetType(int bitmask, String algName, KeyType keyType){
		this.bitmask = bitmask;
		this.cipherName = keyType.alg;
		this.blockSize = keyType.keySize;
		this.algName = algName;
		this.keyType = keyType;
	}
}
