/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CryptBucketType {
	RijndaelECB(1, 256),
	RigndaelECB(2, 256, 128),
	RijndaelCTR(4, 256),
	AESPCFB(8, 256),
	AESCTR(16, 256, "AES/CTR/NOPADDING"),
	AESOCBDraft00(32, 128),
	AESOCB(64, 128);
	
	public final int bitmask;
	public final int keySize;
	public final int blockSize;
	public final String algName;
	
	CryptBucketType(int bitmask, int keySize){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = keySize;
		algName = name();
	}
	
	CryptBucketType(int bitmask, int keySize, int blockSize){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = blockSize;
		algName = name();
	}
	
	CryptBucketType(int bitmask, int keySize, String algName){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = keySize;
		this.algName = algName;
	}
	
}
