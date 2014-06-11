/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.db4o.ObjectContainer;

import freenet.support.api.Bucket;

public class CryptBucket implements Bucket {
	public static final byte ALGO_AES_PCFB_256_SHA256 = 2;
    public static final byte ALGO_AES_CTR_256_SHA256 = 3;
    public static final byte ALGO_CHACHA = 4;
	private byte cryptoAlgorithm;
    private boolean readOnly;
	@Override
	public OutputStream getOutputStream() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public InputStream getInputStream() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public long size() {
		// TODO Auto-generated method stub
		return 0;
	}
	@Override
	public boolean isReadOnly() {
		// TODO Auto-generated method stub
		return false;
	}
	@Override
	public void setReadOnly() {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void free() {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void storeTo(ObjectContainer container) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void removeFrom(ObjectContainer container) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public Bucket createShadow() {
		// TODO Auto-generated method stub
		return null;
	}
}