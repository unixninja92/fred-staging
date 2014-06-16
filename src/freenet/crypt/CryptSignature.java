/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import freenet.node.FSParseException;
import freenet.support.Base64;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;

public class CryptSignature{
	private static final SigType defaultType = 
			PreferredAlgorithms.preferredSignature;
	private SigType type;
	private KeyPair keys;
	private Signature sig;
	
	private DSAPrivateKey dsaPrivK;
	private DSAPublicKey dsaPubK;
	private DSAGroup dsaGroup;

	public CryptSignature(){
		this(defaultType);
	}
	
	public CryptSignature(SimpleFieldSet sfs, SigType type) throws FSParseException{
		this.type = type;
        try {
    		byte[] pub = null;
            byte[] pri = null;
            KeyFactory kf = KeyFactory.getInstance(
            		PreferredAlgorithms.preferredKeyGen, 
            		PreferredAlgorithms.keyGenProvider);
            
            pub = Base64.decode(sfs.get("pub"));
            if (pub.length > type.modulusSize)
                throw new InvalidKeyException();
            X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
            ECPublicKey pubK = (ECPublicKey)kf.generatePublic(xks);
            
            pri = Base64.decode(sfs.get("pri"));
            PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(pri);
            ECPrivateKey privK = (ECPrivateKey) kf.generatePrivate(pks);
            
            keys = new KeyPair(pubK, privK);
            
            sig = type.get();
			sig.initSign(privK);
			sig.initVerify(pubK);
        }  catch (NoSuchAlgorithmException e) {
            Logger.error(ECDSA.class, "NoSuchAlgorithmException : "+e.getMessage(),e);
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            Logger.error(ECDSA.class, "InvalidKeySpecException : "+e.getMessage(), e);
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Logger.error(ECDSA.class, "InvalidKeyException : "+e.getMessage(), e);
			e.printStackTrace();
		} catch (Exception e) {
            throw new FSParseException(e);
        }
	}
	
	public CryptSignature(DSAGroup group, DSAPrivateKey priv, DSAPublicKey pub){
		dsaGroup = group;
		dsaPrivK = priv;
		dsaPubK = pub;
	}
	
	public CryptSignature(DSAPrivateKey priv, DSAPublicKey pub){
		dsaGroup = Global.DSAgroupBigA;
		dsaPrivK = priv;
		dsaPubK = pub;
	}
	
	public CryptSignature(SigType type){
		this.type = type;
		if(type.name()=="DSA"){
			dsaGroup = Global.DSAgroupBigA;
		}
		else {
			try {
				KeyPairGenerator kg = KeyPairGenerator.getInstance(
						PreferredAlgorithms.preferredKeyGen, 
						PreferredAlgorithms.keyGenProvider);
				kg.initialize(type.getSpec());
				keys = kg.generateKeyPair();
				
				sig = type.get();
				sig.initSign(keys.getPrivate());
				sig.initVerify(keys.getPublic());
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
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
        		sig.initSign(keys.getPrivate());
        		for(byte[] b: data){
        			addBytes(b);
        		}
        		result = sig.sign();
        		// It's a DER encoded signature, most sigs will fit in N bytes
                // If it doesn't let's re-sign.
                if(result.length <= type.maxSigSize)
                	break;
                else
                	Logger.error(this, "DER encoded signature used "+result.length+" bytes, more than expected "+type.maxSigSize+" - re-signing...");
        	}
        } catch(SignatureException e){
        	Logger.error(CryptSignature.class, "SignatureException : "+e.getMessage(),e);
        	e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return result;
    }
	
	/**
     * Sign data and return a fixed size signature. The data does not need to be hashed, the 
     * signing code will handle that for us, using an algorithm appropriate for the keysize.
     * @return A zero padded DER signature (maxSigSize). Space Inefficient but constant-size.
     */
    public byte[] signToNetworkFormat(byte[]... data) {
        byte[] plainsig = sign(data);
        int targetLength = type.maxSigSize;

        if(plainsig.length != targetLength) {
            byte[] newData = new byte[targetLength];
            if(plainsig.length < targetLength) {
                System.arraycopy(plainsig, 0, newData, 0, plainsig.length);
            } else {
                throw new IllegalStateException("Too long!");
            }
            plainsig = newData;
        }
        return plainsig;
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
    
    public ECPublicKey getPublicKey() {
        return (ECPublicKey) keys.getPublic();
    }
    
    /**
     * Returns an SFS containing:
     *  - the private key
     *  - the public key
     *  - the name of the curve in use
     *  
     *  It should only be used in NodeCrypto
     * @param includePrivate - include the (secret) private key
     * @return SimpleFieldSet
     */
    public SimpleFieldSet asFieldSet(boolean includePrivate) {
        SimpleFieldSet fs = new SimpleFieldSet(true);
        SimpleFieldSet fsCurve = new SimpleFieldSet(true);
        fsCurve.putSingle("pub", Base64.encode(keys.getPublic().getEncoded()));
        if(includePrivate)
            fsCurve.putSingle("pri", Base64.encode(keys.getPrivate().getEncoded()));
        fs.put(type.name(), fsCurve);
        return fs;
    }
}