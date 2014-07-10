/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public enum KeyType {
	Rijndael128("RIJNDAEL", 128),
	Rijndael256("RIJNDAEL", 256),
	AES128("AES", 128),
	AES256("AES", 256),
	HMACSHA1("HMACSHA1"), 
	HMACSHA256("HMACSHA256"),
	POLY1305("POLY1305-AES"),
	ChaCha("CHACHA", 256);
	
	public final String alg;
	public final int keySize;
	
	KeyType(String alg){
		this.alg = alg;
		this.keySize = -1;
	}
	
	KeyType(String alg, int keySize){
		this.alg = alg;
		this.keySize = keySize;
	}
}
