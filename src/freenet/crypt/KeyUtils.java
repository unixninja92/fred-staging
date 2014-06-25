package freenet.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtils {
	
	public static KeyPair genKeyPair(KeyPairType type) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException{
		KeyPairGenerator kg = KeyPairGenerator.getInstance(
				type.alg, 
				PreferredAlgorithms.keyPairProvider);
		kg.initialize(type.spec);
		return kg.generateKeyPair();
	}
	
	public static PublicKey getPublicKey(byte[] pub){
		try {
			KeyFactory kf = KeyFactory.getInstance(
					PreferredAlgorithms.preferredKeyPairGen, 
					PreferredAlgorithms.keyPairProvider);

	        X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
	        return kf.generatePublic(xks);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static KeyPair getPublicKeyPair(byte[] pub) throws InvalidKeySpecException, NoSuchAlgorithmException{
		return getKeyPair(getPublicKey(pub), null);
	}
	
	public static KeyPair getKeyPair(byte[] pub, byte[] pri) throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory kf = KeyFactory.getInstance(
        		PreferredAlgorithms.preferredKeyPairGen, 
        		PreferredAlgorithms.keyPairProvider);
		
        X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
        PublicKey pubK = kf.generatePublic(xks);
        
        PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(pri);
        PrivateKey privK = kf.generatePrivate(pks);
        
        return getKeyPair(pubK, privK);
	}
	
	public static KeyPair getKeyPair(PublicKey pubK, PrivateKey privK){
		return new KeyPair(pubK, privK);
	}
	
	public static SecretKey genSecretKey(KeyType type){
		try{
			KeyGenerator kg = KeyGenerator.getInstance(type.alg, 
					PreferredAlgorithms.keyGenProviders.get(type.alg));
			if(type.keySize != -1){
				kg.init(type.keySize);
			}
	    	return kg.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return null;
	}
	
	public static SecretKey getSecretKey(byte[] key, KeyType type){
		return new SecretKeySpec(key, type.alg);
	}
}
