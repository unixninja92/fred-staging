/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.util.Arrays;

import com.db4o.ObjectContainer;

import freenet.support.api.Bucket;

public class CryptBucket implements Bucket {
	private static final CryptBucketType defaultType = PreferredAlgorithms.preferredCryptBucketAlg;
	private static final SecureRandom rand = PreferredAlgorithms.sRandom;
	private final CryptBucketType type;
	private final Bucket underlying;
    private SecretKey key;
    private boolean readOnly;
    
    private FilterInputStream is;
    private FilterOutputStream os;
    
    public CryptBucket(Bucket underlying, byte[] key){
    	this(defaultType, underlying, key);
    }
    
    public CryptBucket(CryptBucketType type, Bucket underlying, byte[] key) {
    	this.type = type;
        this.underlying = underlying;
        if(type.equals(CryptBucketType.AESOCB) || type.equals(CryptBucketType.AESOCBDraft00)){
        	boolean isOld = type.equals(CryptBucketType.AESOCBDraft00);
        	this.key = new SecretKeySpec(key, "AES");
        	try {
				is = new AEADInputStream(underlying.getInputStream(), key, new AESEngine(), new AESLightEngine(), isOld);
		        byte[] nonce;
		        if(isOld){
		        	nonce = new byte[16];
		        }else{
		        	nonce = new byte[15];
		        }
		        rand.nextBytes(nonce);
		        nonce[0] &= 0x7F;
				os = new AEADOutputStream(underlying.getOutputStream(), key, nonce, new AESEngine(), new AESLightEngine(), isOld);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }
    }
    
	@Override
	public OutputStream getOutputStream() throws IOException {
		// TODO Auto-generated method stub
		return os;
	}
	
	@Override
	public InputStream getInputStream() throws IOException {
		// TODO Auto-generated method stub
		return is;
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
	public synchronized boolean isReadOnly() {
		// TODO Auto-generated method stub
		return readOnly;
	}
	
	@Override
	public synchronized void setReadOnly() {
		this.readOnly = true;
	}
	
	@Override
	public void free() {
        underlying.free();
	}
	
	@Override
	public void storeTo(ObjectContainer container) {
		underlying.storeTo(container);
        container.store(this);
	}
	
	@Override
	public void removeFrom(ObjectContainer container) {
		underlying.removeFrom(container);
        container.delete(this);
	}
	
	@Override
	public Bucket createShadow() {
		// TODO Auto-generated method stub
		return null;
	}
}