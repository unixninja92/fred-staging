/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CryptBucketType {
	RijndaelECB(1, "Rijndael", 256),
	RigndaelECB(2, "Rijndael", 256, 128),
	RijndaelCTR(4, "Rijndael", 256),
	AESPCFB(8, "AES", 256),
	AESCTR(16, "AES", 256, "AES/CTR/NOPADDING"),
	AEADAESOCBDraft00(32, "AES", 128),
	AEADAESOCB(64, "AES", 128);
	
	public final int bitmask;
	public final int keySize;
	public final int blockSize;
	public final String algName;
	public final String cipherName;
	
	CryptBucketType(int bitmask, String cipherName, int keySize){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keySize = keySize;
		this.blockSize = keySize;
		algName = name();
	}
	
	CryptBucketType(int bitmask, String cipherName, int keySize, int blockSize){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keySize = keySize;
		this.blockSize = blockSize;
		algName = name();
	}
	
	CryptBucketType(int bitmask, String cipherName, int keySize, String algName){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keySize = keySize;
		this.blockSize = keySize;
		this.algName = algName;
	}
	
}
