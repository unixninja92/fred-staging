/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CryptBucketType {
	@Deprecated
	AEADAESOCBDraft00(32, "AES", KeyType.AES128),
	AEADAESOCB(64, "AES", KeyType.AES128);
	
	public final int bitmask;
	public final int keySize;
	public final int blockSize;
	public final String algName;
	public final String cipherName;
	public final KeyType keyType;
	
	CryptBucketType(int bitmask, String cipherName, KeyType keyType){
		this.bitmask = bitmask;
		this.cipherName = cipherName;
		this.keySize = keyType.keySize;
		this.blockSize = keySize;
		algName = name();
		this.keyType = keyType;
	}
	
}
