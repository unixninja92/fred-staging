/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import freenet.crypt.JceLoader;
import freenet.keys.ClientCHKBlock;
import freenet.node.Node;
import freenet.support.Logger;

public class PreferredAlgorithms{
	// static String preferredSignatureProvider;
	private static String preferredSignature = "ECDSA";
	// static String preferredBlockProvider;
	private static String preferredBlock = "AES";
	// static String preferredStreamProvider;
	private static String preferredStream = "ChaCha";
	private static String preferredMesageDigest;

	public final static Provider SUN;
	final static Provider SunJCE;
	final static Provider BC;
	final static Provider NSS;

	private static final Provider hmacProvider;

	public static final Map<String, Provider> mdProviders;
//	public static final Map<String, Provider> sigProviders;
//	public static final Map<String, Provider> blockProviders;
//	public static final Map<String, Provider> streamProviders;
	

	static private long mdBenchmark(MessageDigest md) throws GeneralSecurityException
	{
		long times = Long.MAX_VALUE;
		byte[] input = new byte[1024];
		byte[] output = new byte[md.getDigestLength()];
		// warm-up
		for (int i = 0; i < 32; i++) {
			md.update(input, 0, input.length);
			md.digest(output, 0, output.length);
			System.arraycopy(output, 0, input, (i*output.length)%(input.length-output.length), output.length);
		}
		for (int i = 0; i < 128; i++) {
			long startTime = System.nanoTime();
			for (int j = 0; j < 4; j++) {
				for (int k = 0; k < 32; k ++) {
					md.update(input, 0, input.length);
				}
				md.digest(output, 0, output.length);
			}
			long endTime = System.nanoTime();
			times = Math.min(endTime - startTime, times);
			System.arraycopy(output, 0, input, 0, output.length);
		}
		return times;
	}

	static private long hmacBenchmark(Mac hmac) throws GeneralSecurityException
	{
		long times = Long.MAX_VALUE;
		byte[] input = new byte[1024];
		byte[] output = new byte[hmac.getMacLength()];
		byte[] key = new byte[Node.SYMMETRIC_KEY_LENGTH];
		final String algo = hmac.getAlgorithm();
		hmac.init(new SecretKeySpec(key, algo));
		// warm-up
		for (int i = 0; i < 32; i++) {
			hmac.update(input, 0, input.length);
			hmac.doFinal(output, 0);
			System.arraycopy(output, 0, input, (i*output.length)%(input.length-output.length), output.length);
		}
		System.arraycopy(output, 0, key, 0, Math.min(key.length, output.length));
		for (int i = 0; i < 1024; i++) {
			long startTime = System.nanoTime();
			hmac.init(new SecretKeySpec(key, algo));
			for (int j = 0; j < 8; j++) {
				for (int k = 0; k < 32; k ++) {
					hmac.update(input, 0, input.length);
				}
				hmac.doFinal(output, 0);
			}
			long endTime = System.nanoTime();
			times = Math.min(endTime - startTime, times);
			System.arraycopy(output, 0, input, 0, output.length);
			System.arraycopy(output, 0, key, 0, Math.min(key.length, output.length));
		}
		return times;
	}
	
	static private long cipherBenchmark(Cipher cipher, SecretKeySpec key, IvParameterSpec IV) throws GeneralSecurityException
	{
		long times = Long.MAX_VALUE;
		byte[] input = new byte[1024];
		byte[] output = new byte[input.length*32];
		cipher.init(Cipher.ENCRYPT_MODE, key, IV);
		// warm-up
		for (int i = 0; i < 32; i++) {
			cipher.doFinal(input, 0, input.length, output, 0);
			System.arraycopy(output, 0, input, 0, input.length);
		}
		for (int i = 0; i < 128; i++) {
			long startTime = System.nanoTime();
			cipher.init(Cipher.ENCRYPT_MODE, key, IV);
			for (int j = 0; j < 4; j++) {
				int ofs = 0;
				for (int k = 0; k < 32; k ++) {
					ofs += cipher.update(input, 0, input.length, output, ofs);
				}
				cipher.doFinal(output, ofs);
			}
			long endTime = System.nanoTime();
			times = Math.min(endTime - startTime, times);
			System.arraycopy(output, 0, input, 0, input.length);
		}
		return times;
	}
	
	private static Provider fastest(long time_def, Provider provider_def, long time_sun, long time_bc){
		Provider fastest = provider_def;
		if(time_bc != -1 && time_def > time_bc){
			if(time_sun != -1 && time_bc > time_sun){
				fastest = SUN;
			}
			else{
				fastest = BC;
			}
		}
		else if(time_sun != -1 && time_def > time_sun){
			fastest = SUN;
		}
		return fastest;
	}
	
	static {
		SUN = JceLoader.SUN;
		SunJCE = JceLoader.SunJCE;
		BC = JceLoader.BouncyCastle;
		NSS = JceLoader.NSS;

		final Class<?> clazz = PreferredAlgorithms.class;
		
		//Message Digest Algorithm Benchmarking
		HashMap<String,Provider> mdProviders_internal = new HashMap<String, Provider>();
		for (String algo: new String[] {
				"SHA1", "MD5", "SHA-256", "SHA-384", "SHA-512"
			}) {;
			try {
				MessageDigest md = MessageDigest.getInstance(algo);
				MessageDigest sun_md = null;
				MessageDigest bc_md = null;
				
				long time_def = -1;
				long time_sun = -1;
				long time_bc = -1;
				
				md.digest();
				time_def = mdBenchmark(md);
				System.out.println(algo + " (" + md.getProvider() + "): " + time_def + "ns");
				Logger.minor(clazz, algo + " (" + md.getProvider() + "): " + time_def + "ns");
				try{
					if (SUN != null && md.getProvider() != Security.getProvider("SUN")) {
						sun_md = MessageDigest.getInstance(algo, SUN);
						sun_md.digest();
						time_sun = mdBenchmark(sun_md);
						System.out.println(algo + " (" + sun_md.getProvider() + "): " + time_sun + "ns");
						Logger.minor(clazz, algo + " (" + sun_md.getProvider() + "): " + time_sun + "ns");
					}
				}catch(Throwable e) {
					// ignore
					Logger.error(clazz, algo + "@" + SUN + " benchmark failed", e);
				}
				try{
					if (BC != null) {//should never be null
						bc_md = MessageDigest.getInstance(algo, BC);
						bc_md.digest();
						time_bc = mdBenchmark(bc_md);
						System.out.println(algo + " (" + bc_md.getProvider() + "): " + time_bc + "ns");
						Logger.minor(clazz, algo + " (" + bc_md.getProvider() + "): " + time_bc + "ns");
					}
				}catch(Throwable e) {
					// ignore
					Logger.error(clazz, algo + "@" + BC + " benchmark failed", e);
				}
				
				Provider mdProvider = fastest(time_def, md.getProvider(), time_sun, time_bc);
				System.out.println(algo + ": using " + mdProvider);
				Logger.normal(clazz, algo + ": using " + mdProvider);
				mdProviders_internal.put(algo, mdProvider);
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				throw new Error(e);
			}
			
		}
		mdProviders = Collections.unmodifiableMap(mdProviders_internal);
		
		
		//HMAC Benchmarking
		final String algo = "HmacSHA256";
		try{
			SecretKeySpec dummyKey = new SecretKeySpec(new byte[Node.SYMMETRIC_KEY_LENGTH], algo);
			Mac hmac = Mac.getInstance(algo);
			Mac sun_hmac = null;
			Mac bc_hmac = null;
			
			long time_def = -1;
			long time_sun = -1;
			long time_bc = -1;
			
			hmac.init(dummyKey); // resolve provider
			time_def = hmacBenchmark(hmac);
			System.out.println(algo + " (" + hmac.getProvider() + "): " + time_def + "ns");
			Logger.minor(clazz, algo + "/" + hmac.getProvider() + ": " + time_def + "ns");
			
			if (SUN != null && hmac.getProvider() != Security.getProvider("SUN")) {
//				// SunJCE provider is faster (in some configurations)
				try {
					sun_hmac = Mac.getInstance(algo, SUN);
					sun_hmac.init(dummyKey);
					time_sun = hmacBenchmark(sun_hmac);
					System.out.println(algo + " (" + sun_hmac.getProvider() + "): " + time_sun + "ns");
					Logger.minor(clazz, algo + "/" + sun_hmac.getProvider() + ": " + time_sun + "ns");
				} catch(GeneralSecurityException e) {
					Logger.warning(clazz, algo + "@" + SUN + " benchmark failed", e);
					// ignore

				} catch(Throwable e) {
					Logger.error(clazz, algo + "@" + SUN + " benchmark failed", e);
					// ignore
				}
			}
			if (BC != null){
				try {
					bc_hmac = Mac.getInstance(algo, BC);
					bc_hmac.init(dummyKey);
					time_sun = hmacBenchmark(bc_hmac);
					System.out.println(algo + " (" + bc_hmac.getProvider() + "): " + time_bc + "ns");
					Logger.minor(clazz, algo + "/" + bc_hmac.getProvider() + ": " + time_bc + "ns");
				} catch(GeneralSecurityException e) {
					Logger.warning(clazz, algo + "@" + BC + " benchmark failed", e);
					// ignore

				} catch(Throwable e) {
					Logger.error(clazz, algo + "@" + BC + " benchmark failed", e);
					// ignore
				}
			}
			hmacProvider = fastest(time_def, hmac.getProvider(), time_sun, time_bc);
			System.out.println(algo + ": using " + hmacProvider);
			Logger.normal(clazz, algo + ": using " + hmacProvider);
		}catch(GeneralSecurityException e){
			throw new Error(e);
		}
		
	}

//	static {
//	
//	private static Provider getAesCtrProvider() {
//		try {
//			final String algo = "AES/CTR/NOPADDING";
//			final Provider bcastle = JceLoader.BouncyCastle;
//
//			byte[] key = new byte[32]; // Test for whether 256-bit works.
//			byte[] iv = new byte[16];
//			byte[] plaintext = new byte[16];
//			SecretKeySpec k = new SecretKeySpec(key, "AES");
//			IvParameterSpec IV = new IvParameterSpec(iv);
//
//			Cipher c = Cipher.getInstance(algo);
//			c.init(Cipher.ENCRYPT_MODE, k, IV);
//			// ^^^ resolve provider
//			Provider provider = c.getProvider();
//			if (bcastle != null) {
//				// BouncyCastle provider is faster (in some configurations)
//				try {
//					Cipher bcastle_cipher = Cipher.getInstance(algo, bcastle);
//					bcastle_cipher.init(Cipher.ENCRYPT_MODE, k, IV);
//					Provider bcastle_provider = bcastle_cipher.getProvider();
//					if (provider != bcastle_provider) {
//						long time_def = cipherBenchmark(c, k, IV);
//						long time_bcastle = cipherBenchmark(bcastle_cipher, k, IV);
//						System.out.println(algo + " (" + provider + "): " + time_def + "ns");
//						System.out.println(algo + " (" + bcastle_provider + "): " + time_bcastle + "ns");
////						Logger.minor(clazz, algo + "/" + provider + ": " + time_def + "ns");
////						Logger.minor(clazz, algo + "/" + bcastle_provider + ": " + time_bcastle + "ns");
//						if (time_bcastle < time_def) {
//							provider = bcastle_provider;
//							c = bcastle_cipher;
//						}
//					}
//				} catch(GeneralSecurityException e) {
//					// ignore
////					Logger.warning(clazz, algo + "@" + bcastle + " benchmark failed", e);
//
//				} catch(Throwable e) {
//					// ignore
////					Logger.error(clazz, algo + "@" + bcastle + " benchmark failed", e);
//				}
//			}
//			c = Cipher.getInstance(algo, provider);
//			c.init(Cipher.ENCRYPT_MODE, k, IV);
//			c.doFinal(plaintext);
////			Logger.normal(Rijndael.class, "Using JCA: provider "+provider);
//			System.out.println("Using JCA cipher provider: "+provider);
//			return provider;
//		} catch (GeneralSecurityException e) {
////			Logger.warning(Rijndael.class, "Not using JCA as it is crippled (can't use 256-bit keys). Will use built-in encryption. ", e);
//			return null;
//		}
//	}
}