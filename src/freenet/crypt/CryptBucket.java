/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;

import com.db4o.ObjectContainer;

import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.io.ArrayBucket;
import freenet.support.io.ArrayBucketFactory;

public final class CryptBucket implements Bucket {
	private static final CryptBucketType defaultType = PreferredAlgorithms.preferredCryptBucketAlg;
	private static final SecureRandom rand = PreferredAlgorithms.sRandom;
	private final CryptBucketType type;
	private final Bucket underlying;
    private SecretKey key;
    private boolean readOnly;
    private byte[] iv = null;
    
//    private FilterInputStream is;
    private FilterOutputStream outStream;
    
  //FIXME make per type
    private final int OVERHEAD = AEADOutputStream.AES_OVERHEAD;
    
    public CryptBucket(long size) throws IOException{
    	this(defaultType, size);
    }
    
    public CryptBucket(CryptBucketType type, long size, byte[] key) throws IOException{
    	this(type, new ArrayBucketFactory(), size, key);
    }
    
    public CryptBucket(CryptBucketType type, long size) throws IOException{
    	this(type, new ArrayBucketFactory(), size);
    }
    
    private CryptBucket(CryptBucketType type, BucketFactory bf, long size) throws IOException{
    	this(type, bf.makeBucket(size));
    }
    
    private CryptBucket(CryptBucketType type, BucketFactory bf, long size, byte[] key) throws IOException{
    	this(type, bf.makeBucket(size), key);
    }
    
    public CryptBucket(Bucket underlying, byte[] key){
    	this(defaultType, underlying, key);
    }
    
    public CryptBucket(CryptBucketType type, Bucket underlying, byte[] key){
    	this(type, underlying, KeyUtils.getSecretKey(key, type.keyType), false);
    }
    
    public CryptBucket(CryptBucketType type, Bucket underlying){
    	this(type, underlying, KeyUtils.genSecretKey(type.keyType), false);
    }
    
    public CryptBucket(CryptBucketType type, Bucket underlying, SecretKey key, boolean readOnly) {
    	this.type = type;
        this.underlying = underlying;
        this.key = key;
        this.readOnly = readOnly;
    }
    
    public final byte[] decrypt(){
    	byte[] plain = new byte[(int) size()];
    	try {
    		FilterInputStream is = genInputStream();
			is.read(plain);
			is.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return plain;
    }
    
    private final void checkOutStream() throws IOException{
    	if(!readOnly){
    		if(outStream == null){
    			outStream = genOutputStream();
    		}
    	}
    	else{
    		throw new IOException("Read only");
    	}
    }
    
    public final void addByte(byte input) throws IOException{
    	checkOutStream();
    	try {
    		outStream.write(input);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public final void addBytes(byte[]... input) throws IOException{
    	checkOutStream();
    	try {
			for(byte[] b: input){
				outStream.write(b);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public final void addBytes(byte[] input, int offset, int len) throws IOException{
    	checkOutStream();
    	try {
    		outStream.write(input, offset, len);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public final void encrypt() throws IOException{
    	if(outStream == null){
    		throw new IOException();
    	}
    	checkOutStream();
    	outStream.close();
    	outStream = null;
    }
    
    public final void encrypt(byte[]... input) throws IOException{
    	addBytes(input);
    	encrypt();
    }
    
	@Override
    public OutputStream getOutputStream() throws IOException {
    	return genOutputStream();
    }
	
	private final FilterOutputStream genOutputStream() throws IOException {
		if(type.equals(CryptBucketType.AEADAESOCB) || type.equals(CryptBucketType.AEADAESOCBDraft00)){
			boolean isOld = type.equals(CryptBucketType.AEADAESOCBDraft00);

			byte[] nonce;
			if(isOld){
				nonce = new byte[16];
			}else{
				nonce = new byte[15];
			}
			rand.nextBytes(nonce);
			nonce[0] &= 0x7F;

			return new AEADOutputStream(underlying.getOutputStream(), 
					key.getEncoded(), nonce, new AESFastEngine(), 
					new AESLightEngine(), isOld);
		}
		else{
			if(iv == null){
				iv = new byte[type.blockSize >> 3];
				rand.nextBytes(iv);
			}
			
			try {
				return new SymmetricOutputStream(underlying.getOutputStream(), type, key.getEncoded(), iv);
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | UnsupportedCipherException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
        throw new IOException();
	}
	
	@Override
	public InputStream getInputStream() throws IOException {
		return genInputStream();
	}
	
	private final FilterInputStream genInputStream() throws IOException {
        if(type.equals(CryptBucketType.AEADAESOCB) || type.equals(CryptBucketType.AEADAESOCBDraft00)){
        	return new AEADInputStream(underlying.getInputStream(), 
        			key.getEncoded(), new AESFastEngine(), new AESLightEngine(), 
        			type.equals(CryptBucketType.AEADAESOCBDraft00));
        }
        else{
        	try {
				return new SymmetricInputStream(underlying.getInputStream(), type, key.getEncoded(), type.blockSize >> 3);
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | UnsupportedCipherException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }
        throw new IOException();
	}
	
	@Override
	public String getName() {
		return type.name();
	}
	
	@Override
	public final long size() {
        return underlying.size() - OVERHEAD;
	}
	
	@Override
	public final synchronized boolean isReadOnly() {
		return readOnly;
	}
	
	@Override
	public final synchronized void setReadOnly() {
		this.readOnly = true;
	}
	
	public final byte[] getIV(){
		return iv;
	}
	
	public final void setIV(byte[] iv){
		this.iv = iv;
	}
	
	@Override
	public final void free() {
        underlying.free();
	}
	
	@Override
	public final void storeTo(ObjectContainer container) {
		underlying.storeTo(container);
        container.store(this);
	}
	
	@Override
	public final void removeFrom(ObjectContainer container) {
		underlying.removeFrom(container);
        container.delete(this);
	}
	
	@Override
	public final Bucket createShadow() {
        Bucket undershadow = underlying.createShadow();
        CryptBucket ret = new CryptBucket(undershadow, key.getEncoded());
        ret.setReadOnly();
		return ret;
	}
	
	public byte[] toByteArray(){
		return ((ArrayBucket)underlying).toByteArray();
	}
}