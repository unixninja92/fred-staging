/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;

import freenet.support.Logger;
import net.i2p.util.NativeBigInteger;

public class CryptSignature{
	private static final SigType defaultType = PreferredAlgorithms.preferredSignature;
	private KeyPair keys;
	private Signature sig;
	private KeyPairGenerator kg;

	public CryptSignature(){
		try {
			kg = KeyPairGenerator.getInstance(PreferredAlgorithms.preferredKeyGen, 
					PreferredAlgorithms.keyGenProvider);
			kg.initialize(defaultType.getSpec());
			keys = kg.generateKeyPair();
			
			sig = defaultType.get();
			sig.initSign(keys.getPrivate());
			sig.initVerify(keys.getPublic());
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addByte(byte input){
		try {
			sig.update(input);
		} catch (SignatureException e) {
			Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
	}
	
	public void addBytes(byte[] input){
		try {
			sig.update(input);
		} catch (SignatureException e) {
			Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
	}

	public void addBytes(byte[] data, int offset, int length){
		try {
			sig.update(data, offset, length);
		} catch (SignatureException e) {
			Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
	}
	
	public void addBytes(ByteBuffer input){
		try {
			sig.update(input);
		} catch (SignatureException e) {
			Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
	}
	
	public byte[] sign(byte[]... data) {
        byte[] result = null;
        try{
        	while(true) {
//        		sig.initSign(keys.getPrivate());
        		for(byte[] b: data){
        			addBytes(b);
        		}
        		result = sig.sign();
        		// It's a DER encoded signature, most sigs will fit in N bytes
                // If it doesn't let's re-sign.
                if(result.length <= defaultType.maxSigSize)
                	break;
                else
                	Logger.error(this, "DER encoded signature used "+result.length+" bytes, more than expected "+defaultType.maxSigSize+" - re-signing...");
        	}
        } catch(SignatureException e){
        	Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
        	e.printStackTrace();
//        } catch (InvalidKeyException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
		}
        return result;
    }

	public boolean verify(byte[] signature){
		try {
			return sig.verify(signature);
		} catch (SignatureException e) {
            Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
		return false;
	}
	
    public boolean verify(byte[] signature, byte[]... data){
		try {
			for(byte[] b: data){
				addBytes(b);
			}
			return sig.verify(signature);
		} catch (SignatureException e) {
			Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
			e.printStackTrace();
		}
    	return false;
    }
}