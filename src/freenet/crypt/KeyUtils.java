/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import freenet.support.Logger;

public class KeyUtils {
	
	/**
	 * Generates a public/private key pair
	 * @param type Kind of key pair to generate
	 * @return Returns the generated key pair
	 */
	public static KeyPair genKeyPair(KeyPairType type){
		try {
			KeyPairGenerator kg = KeyPairGenerator.getInstance(
					type.alg, 
					PreferredAlgorithms.keyPairProvider);
			kg.initialize(type.spec);
			return kg.generateKeyPair();
		} catch (GeneralSecurityException e) {
			Logger.error(KeyUtils.class, "Internal error; please report:", e);
        } 
		return null;
	}
	
	/**
	 * Converts byte[] to public key
	 * @param pub Public key as byte[]
	 * @return Public key as PublicKey
	 */
	public static PublicKey getPublicKey(byte[] pub){
		try {
			KeyFactory kf = KeyFactory.getInstance(
					PreferredAlgorithms.preferredKeyPairGen, 
					PreferredAlgorithms.keyPairProvider);

	        X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
	        return kf.generatePublic(xks);
		} catch (GeneralSecurityException e) {
			Logger.error(KeyUtils.class, "Internal error; please report:", e);
		}
		return null;
	}
	
	/**
	 * Converts byte[] to KeyPair
	 * @param pub Public key as byte[]
	 * @return Public key as KeyPair with null private key
	 */
	public static KeyPair getPublicKeyPair(byte[] pub){
		return getKeyPair(getPublicKey(pub), null);
	}
	
	/**
	 * Converts public and private key byte[]s to KeyPair
	 * @param pub Public key
	 * @param pri Private key
	 * @return The public key and private key in a KeyPair
	 */
	public static KeyPair getKeyPair(byte[] pub, byte[] pri){
		try {
			KeyFactory kf = KeyFactory.getInstance(
	        		PreferredAlgorithms.preferredKeyPairGen, 
	        		PreferredAlgorithms.keyPairProvider);
			
	        X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
			PublicKey pubK = kf.generatePublic(xks);
			
	        PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(pri);
	        PrivateKey privK = kf.generatePrivate(pks);

	        return getKeyPair(pubK, privK);
		} catch (GeneralSecurityException e) {
			Logger.error(KeyUtils.class, "Internal error; please report:", e);
		}
        return null;
	}
	
	/**
	 * Combines the PublicKey and PrivateKey into a KeyPair
	 * @param pubK Public key
	 * @param privK Private key
	 * @return The public key and private key in a KeyPair
	 */
	public static KeyPair getKeyPair(PublicKey pubK, PrivateKey privK){
		return new KeyPair(pubK, privK);
	}
	
	/**
	 * Generates a secret key for the specified algorithm
	 * @param type Type of key to generate
	 * @return Generated key
	 */
	public static SecretKey genSecretKey(KeyType type){
		try{
			KeyGenerator kg = KeyGenerator.getInstance(type.alg, 
					PreferredAlgorithms.keyGenProviders.get(type.alg));
			if(type.keySize != -1){
				kg.init(type.keySize);
			}
	    	return kg.generateKey();
		} catch (NoSuchAlgorithmException e) {
			Logger.error(KeyUtils.class, "Internal error; please report:", e);
		}
    	return null;
	}
	
	/**
	 * Converts a key byte[] into a SecretKey for the specified algorithm
	 * @param key The byte[] of the key
	 * @param type Type of key
	 * @return The key as a SecretKey
	 */
	public static SecretKey getSecretKey(byte[] key, KeyType type){
		return new SecretKeySpec(key, type.alg);
	}
}
