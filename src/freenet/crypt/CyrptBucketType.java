/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum CyrptBucketType {
	RijndaelECB(1, 128),
	AESPCFB(2, 128),
	AESCTR(4, 128),
	AESOCB(8, 128);
	
	public final int bitmask;
	public final int keySize;
	
	CyrptBucketType(int bitmask, int keySize){
		this.bitmask = bitmask;
		this.keySize = keySize;
	}
}
