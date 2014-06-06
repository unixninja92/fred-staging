/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;

import net.i2p.util.NativeBigInteger;

public class Signature{
	private String algorithm; 
	private String provider;
	private KeyPair key;

	public Signature(){

	}
	
	public byte[] sign(byte[]... data) {
        byte[] result = null;
        
        return result;
    }

    public boolean verify(byte[] signature, byte[]... data){
    	return false;
    }
}