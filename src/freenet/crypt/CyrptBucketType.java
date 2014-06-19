/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CyrptBucketType {
	RijndaelECB(1, 256),
	RijndaelCTR(2, 256),
	AESPCFB(4, 256),
	AESCTR(8, 256, "AES/CTR/NOPADDING"),
	AESOCB(16, 128);
	
	public final int bitmask;
	public final int keySize;
	public final int blockSize;
	public final String algName;
	
	CyrptBucketType(int bitmask, int keySize){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = keySize;
		algName = name();
	}
	
	CyrptBucketType(int bitmask, int keySize, int blockSize){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = blockSize;
		algName = name();
	}
	
	CyrptBucketType(int bitmask, int keySize, String algName){
		this.bitmask = bitmask;
		this.keySize = keySize;
		this.blockSize = keySize;
		this.algName = algName;
	}
}
