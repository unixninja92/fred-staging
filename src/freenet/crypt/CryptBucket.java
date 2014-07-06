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

import com.db4o.ObjectContainer;

import freenet.support.api.Bucket;

/**
 * CryptBucket is a bucket filter that encrypts all data going to the underlying
 * bucket and decrypts all data read from the underlying bucket. This is done using
 * AEAD.
 * Warning: 
 * Avoid using Closer.close() on InputStream's opened on this Bucket. The MAC is only 
 * checked when the end of the bucket is reached, which may be in read() or may 
 * be in close().
 */
public final class CryptBucket implements Bucket {
	private static final CryptBucketType defaultType = PreferredAlgorithms.preferredCryptBucketAlg;
	private static final SecureRandom rand = PreferredAlgorithms.sRandom;
	private final CryptBucketType type;
	private final Bucket underlying;
    private SecretKey key;
    private boolean readOnly;
    
    /*
     * The output stream that addBytes methods will work with. 
     */
    private FilterOutputStream outStream;
    
    private final int OVERHEAD = AEADOutputStream.AES_OVERHEAD;

    /**
     * Creates instance of CryptBucket using the default algorithm and generates a key
     * to encrypt and decrypt the underlying bucket
     * @param underlying The bucket that will be storing the encrypted data
     */
    public CryptBucket(Bucket underlying){
    	this(defaultType, underlying, KeyUtils.genSecretKey(defaultType.keyType));
    }
    
    /**
     * Creates instance of CryptBucket using the algorithm type and generates a key
     * to encrypt and decrypt the underlying bucket
     * @param type What kind of cipher and mode to use for encryption
     * @param underlying The bucket that will be storing the encrypted data
     */
    public CryptBucket(CryptBucketType type, Bucket underlying){
    	this(type, underlying, KeyUtils.genSecretKey(type.keyType));
    }  
    
    /**
     * Creates instance of CryptBucket using the algorithm type with the specified key
     * to encrypt and decrypt the underlying bucket
     * @param type What kind of cipher and mode to use for encryption
     * @param underlying The bucket that will be storing the encrypted data
     * @param key The key that will be used for encryption
     */
    public CryptBucket(CryptBucketType type, Bucket underlying, byte[] key){
    	this(type, underlying, KeyUtils.getSecretKey(key, type.keyType));
    }
    
    /**
     * Creates instance of CryptBucket using the algorithm type with the specified key
     * to encrypt and decrypt the underlying bucket
     * @param type What kind of cipher and mode to use for encryption
     * @param underlying The bucket that will be storing the encrypted data
     * @param key The key that will be used for encryption
     */
    public CryptBucket(CryptBucketType type, Bucket underlying, SecretKey key){
    	this(type, underlying, key, false);
    }
    
    /**
     * Creates instance of CryptBucket using the algorithm type with the specified key
     * to decrypt the underlying bucket and encrypt it as well if it is not readOnly
     * @param type What kind of cipher and mode to use for encryption
     * @param underlying The bucket that will be storing the encrypted data
     * @param key The key that will be used for encryption
     * @param readOnly Sets if the bucket will be read-only 
     */
    public CryptBucket(CryptBucketType type, Bucket underlying, SecretKey key, boolean readOnly) {
    	this.type = type;
        this.underlying = underlying;
        this.key = key;
        this.readOnly = readOnly;
    }

	/**
     * Decrypts the data in the underlying bucket.
     * @return Returns the unencrypted data in a byte[]
	 * @throws IOException 
     */
    public final byte[] decrypt() throws IOException{
    	byte[] plain = new byte[(int) size()];
    	FilterInputStream is = genInputStream();
    	is.read(plain);
    	is.close();
    	return plain;
    }
    
    /**
     * Checks if an output/encryption stream has been generated yet.
     * If one hasen't then it generates one. 
     * @throws IOException
     */
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
    
    /**
     * Adds a byte to be encrypted into the underlying bucket
     * @param input Byte to be encrypted
     * @throws IOException
     */
    public final void addByte(byte input) throws IOException{
    	checkOutStream();
    	outStream.write(input);
    }
    
    /**
     * Adds byte[]s to be encrypted into the underlying bucket
     * @param input Any number of byte[]s to be encrypted
     * @throws IOException
     */
    public final void addBytes(byte[]... input) throws IOException{
    	checkOutStream();
    	for(byte[] b: input){
    		outStream.write(b);
    	}
    }
    
    /**
     * Adds a selection of a byte[] to be encrypted into the underlying bucket
     * @param input The byte[] to encrypt
     * @param offset Where in the byte[] to start encrypting
     * @param len How many bytes after offset to encrypt and send to underlying bucket
     * @throws IOException
     */
    public final void addBytes(byte[] input, int offset, int len) throws IOException{
    	checkOutStream();
    	outStream.write(input, offset, len);
    }
    
    /**
     * Completes the encryption of the underlying bucket and closes the output stream. 
     * @throws IOException
     */
    public final void encrypt() throws IOException{
    	if(outStream == null){
    		throw new IOException("No data to encrypt");
    	}
    	checkOutStream();
    	outStream.close();
    	outStream = null;
    }
    
    /**
     * Encrypts input and places the encrypted result in the underlying bucket. 
     * @param input They byte[]s to be encrypted
     * @throws IOException
     */
    public final void encrypt(byte[]... input) throws IOException{
    	addBytes(input);
    	encrypt();
    }
    
	@Override
    public OutputStream getOutputStream() throws IOException {
    	return genOutputStream();
    }
	
	/**
	 * Generates a random nonce and returns an encrypting FilterOutputStream
	 * @return Returns an AEADOutputStream
	 * @throws IOException
	 */
	private final FilterOutputStream genOutputStream() throws IOException {
		byte[] nonce = new byte[type.nonceSize];
		rand.nextBytes(nonce);
		nonce[0] &= 0x7F;

		return new AEADOutputStream(underlying.getOutputStream(), 
				key.getEncoded(), nonce, type);
	}
	
	@Override
	public InputStream getInputStream() throws IOException {
		return genInputStream();
	}
	
	/**
	 * Returns an encrypting FilterInputStream
	 * @return Returns an AEADInputStream
	 * @throws IOException
	 */
	private final FilterInputStream genInputStream() throws IOException {
		return new AEADInputStream(underlying.getInputStream(), 
        			key.getEncoded(), type);
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
        CryptBucket ret = new CryptBucket(type, undershadow, key, true);
		return ret;
	}
}