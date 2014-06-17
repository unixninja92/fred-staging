/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import freenet.crypt.JceLoader;
import freenet.node.Node;
import freenet.support.Logger;

public class PreferredAlgorithms{
	public static SigType preferredSignature = SigType.ECDSAP256;
	public static String preferredKeyGen = "EC";
	public static HashType preferredMesageDigest = HashType.SHA256;
	public static MACType preferredMAC = MACType.HMACSHA256;//FIXME will be poly1305

	final static Provider SUN;
	final static Provider SunJCE;
	final static Provider BC;
	final static Provider NSS;

	public static final Provider hmacProvider;
	public static Provider aesCTRProvider; 
	public static final Provider keyGenProvider;
//	public static final Provider signatureProvider;
	
	public static final Map<String, Provider> mdProviders;
	public static final Map<String, Provider> sigProviders;
	
	public static RandomSource random;

	static public void setRandomSource(RandomSource r){
		random = r;
	}
	
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

	static private long macBenchmark(Mac mac) throws GeneralSecurityException
	{
		long times = Long.MAX_VALUE;
		byte[] input = new byte[1024];
		byte[] output = new byte[mac.getMacLength()];
		byte[] key = new byte[Node.SYMMETRIC_KEY_LENGTH];
		final String algo = mac.getAlgorithm();
		mac.init(new SecretKeySpec(key, algo));
		// warm-up
		for (int i = 0; i < 32; i++) {
			mac.update(input, 0, input.length);
			mac.doFinal(output, 0);
			System.arraycopy(output, 0, input, (i*output.length)%(input.length-output.length), output.length);
		}
		System.arraycopy(output, 0, key, 0, Math.min(key.length, output.length));
		for (int i = 0; i < 128; i++) {
			long startTime = System.nanoTime();
			mac.init(new SecretKeySpec(key, algo));
			for (int j = 0; j < 8; j++) {
				for (int k = 0; k < 32; k ++) {
					mac.update(input, 0, input.length);
				}
				mac.doFinal(output, 0);
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
	
	static private long keyFactoryBenchmark(KeyPairGenerator kg, KeyFactory kf) 
			throws NoSuchAlgorithmException, InvalidKeySpecException 
			{
		long times = Long.MAX_VALUE;
		int modulusSize = 91;
		KeyPair key;
		PublicKey pub;
		PrivateKey pk;
		byte [] pubkey;
		byte [] pkey;
		PublicKey pub2;
		PrivateKey pk2;
		//warmup
		for (int i = 0; i < 32; i++) {
			key = kg.generateKeyPair();
			pub = key.getPublic();
			pk = key.getPrivate();
			pubkey = pub.getEncoded();
			pkey = pk.getEncoded();
			if(pubkey.length > modulusSize || pubkey.length == 0)
				throw new Error("Unexpected pubkey length: "+pubkey.length+"!="+modulusSize);
			
			pub2 = kf.generatePublic(
					new X509EncodedKeySpec(pubkey)
					);
			if(!Arrays.equals(pub2.getEncoded(), pubkey))
				throw new Error("Pubkey encoding mismatch");
			pk2 = kf.generatePrivate(
					new PKCS8EncodedKeySpec(pkey)
					);
		}
		for (int i = 0; i < 128; i++) {
			long startTime = System.nanoTime();
			
			key = kg.generateKeyPair();
			pub = key.getPublic();
			pk = key.getPrivate();
			pubkey = pub.getEncoded();
			pkey = pk.getEncoded();

			pub2 = kf.generatePublic(
					new X509EncodedKeySpec(pubkey)
					);

			pk2 = kf.generatePrivate(
					new PKCS8EncodedKeySpec(pkey)
					);

			long endTime = System.nanoTime();
			times = Math.min(endTime - startTime, times);
		}
		return times;
	}
	
	static private long signatureBenchmark(Signature sig, SigType type)
			throws GeneralSecurityException
	{
		long times = Long.MAX_VALUE;
		int modulusSize = type.modulusSize;
		
		Provider provider = keyGenProvider;//sig.getProvider();
		
        ECGenParameterSpec spec = new ECGenParameterSpec(type.specName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(preferredKeyGen, provider);
		kpg.initialize(spec);
        
        KeyPair key = kpg.generateKeyPair();
		KeyFactory kf = KeyFactory.getInstance(preferredKeyGen, provider);
		PublicKey pub = key.getPublic();
        PrivateKey pk = key.getPrivate();
        byte [] pubkey = pub.getEncoded();
        byte [] pkey = pk.getEncoded();
		if(pubkey.length > modulusSize || pubkey.length == 0)
			throw new Error("Unexpected pubkey length: "+pubkey.length+"!="+modulusSize);
        PublicKey pub2 = kf.generatePublic(
                new X509EncodedKeySpec(pubkey)
                );
        if(!Arrays.equals(pub2.getEncoded(), pubkey))
            throw new Error("Pubkey encoding mismatch");
        PrivateKey pk2 = kf.generatePrivate(
                new PKCS8EncodedKeySpec(pkey)
                );
        
		//warmup
		for (int i = 0; i < 32; i++) {
			sig.initSign(key.getPrivate());
			byte[] sign = sig.sign();
			sig.initVerify(key.getPublic());
			boolean verified = sig.verify(sign);
			if (!verified)
				throw new Error("Verification failed");
		}
		for (int i = 0; i < 128; i++) {
			long startTime = System.nanoTime();
		
			sig.initSign(key.getPrivate());
			byte[] sign = sig.sign();
			sig.initVerify(key.getPublic());
			sig.verify(sign);
			
			long endTime = System.nanoTime();
			times = Math.min(endTime - startTime, times);
		}
		return times;
	}
	
	private static Provider fastest(long time_def, Provider provider_def, long time_sun, long time_nss, long time_bc){
		Provider fastest = provider_def;
		if(time_def > time_bc){
			if(time_bc > time_sun && time_nss > time_sun){
				fastest = SUN;
			}
			else if(time_bc > time_nss){
				fastest = NSS;
			}
			else{
				fastest = BC;
			}
		}
		else if(time_def > time_sun && time_nss > time_sun){
			fastest = SUN;
		}
		else if(time_def > time_nss){
			fastest = NSS;
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
				MessageDigest nss_md = null;
				MessageDigest bc_md = null;
				
				long time_def = Long.MAX_VALUE;
				long time_sun = Long.MAX_VALUE;
				long time_nss = Long.MAX_VALUE;
				long time_bc = Long.MAX_VALUE;
				
				md.digest();
				time_def = mdBenchmark(md);
				System.out.println(algo + " (" + md.getProvider() + "): " + time_def + "ns");
				Logger.minor(clazz, algo + " (" + md.getProvider() + "): " + time_def + "ns");
				try{
					if (SUN != null && md.getProvider() != SUN) {
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
					if (NSS != null) {
						nss_md = MessageDigest.getInstance(algo, NSS);
						nss_md.digest();
						time_nss = mdBenchmark(nss_md);
						System.out.println(algo + " (" + nss_md.getProvider() + "): " + time_nss + "ns");
						Logger.minor(clazz, algo + " (" + nss_md.getProvider() + "): " + time_nss + "ns");
					}
				}catch(Throwable e) {
					// ignore
					Logger.error(clazz, algo + "@" + NSS + " benchmark failed", e);
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
				
				Provider mdProvider = fastest(time_def, md.getProvider(), time_sun, time_nss, time_bc);
				System.out.println(algo + ": using " + mdProvider);
				Logger.normal(clazz, algo + ": using " + mdProvider);
				mdProviders_internal.put(algo, mdProvider);
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				throw new Error(e);
			}
			
		}
		mdProviders = Collections.unmodifiableMap(mdProviders_internal);
		

		String algo;
		
		//HMAC Benchmarking
		algo = "HmacSHA256";
		try{
			SecretKeySpec dummyKey = new SecretKeySpec(new byte[Node.SYMMETRIC_KEY_LENGTH], algo);
			Mac hmac = Mac.getInstance(algo);
			Mac sun_hmac = null;
			Mac nss_hmac = null;
			Mac bc_hmac = null;
			
			long time_def = Long.MAX_VALUE;
			long time_sun = Long.MAX_VALUE;
			long time_nss = Long.MAX_VALUE;
			long time_bc = Long.MAX_VALUE;
			
			hmac.init(dummyKey); // resolve provider
			time_def = macBenchmark(hmac);
			System.out.println(algo + " (" + hmac.getProvider() + "): " + time_def + "ns");
			Logger.minor(clazz, algo + "/" + hmac.getProvider() + ": " + time_def + "ns");
			
			if (SUN != null && hmac.getProvider() != SUN) {
//				// SunJCE provider is faster (in some configurations)
				try {
					sun_hmac = Mac.getInstance(algo, SUN);
					sun_hmac.init(dummyKey);
					time_sun = macBenchmark(sun_hmac);
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
			if (NSS != null){
				try {
					nss_hmac = Mac.getInstance("HMACSHA256", NSS);
					nss_hmac.init(dummyKey);
					time_nss = macBenchmark(nss_hmac);
					System.out.println(algo + " (" + nss_hmac.getProvider() + "): " + time_nss + "ns");
					Logger.minor(clazz, algo + "/" + nss_hmac.getProvider() + ": " + time_nss + "ns");
				} catch(GeneralSecurityException e) {
					Logger.warning(clazz, algo + "@" + NSS + " benchmark failed", e);
					// ignore

				} catch(Throwable e) {
					Logger.error(clazz, algo + "@" + NSS + " benchmark failed", e);
					// ignore
				}
			}
			if (BC != null){
				try {
					bc_hmac = Mac.getInstance("HMACSHA256", BC);
					bc_hmac.init(dummyKey);
					time_bc = macBenchmark(bc_hmac);
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
			hmacProvider = fastest(time_def, hmac.getProvider(), time_sun, time_nss, time_bc);
			System.out.println(algo + ": using " + hmacProvider);
			Logger.normal(clazz, algo + ": using " + hmacProvider);
		}catch(GeneralSecurityException e){
			throw new Error(e);
		}
		
		
		//Cipher Benchmarking
		algo = "AES/CTR/NOPADDING";
		try{
			byte[] key = new byte[32]; // Test for whether 256-bit works.
			byte[] iv = new byte[16];
			byte[] plaintext = new byte[16];
			SecretKeySpec k = new SecretKeySpec(key, "AES");
			IvParameterSpec IV = new IvParameterSpec(iv);
			Cipher c = Cipher.getInstance(algo);
			c.init(Cipher.ENCRYPT_MODE, k, IV);
			Provider provider = c.getProvider();
			try{
				if(BC != null && provider != BC){
					Cipher bcastle_cipher = Cipher.getInstance(algo, BC);
					bcastle_cipher.init(Cipher.ENCRYPT_MODE, k, IV);
					long time_def = cipherBenchmark(c, k, IV);
					long time_bcastle = cipherBenchmark(bcastle_cipher, k, IV);
					System.out.println(algo + " (" + provider + "): " + time_def + "ns");
					System.out.println(algo + " (" + BC + "): " + time_bcastle + "ns");
					Logger.minor(clazz, algo + "/" + provider + ": " + time_def + "ns");
					Logger.minor(clazz, algo + "/" + BC + ": " + time_bcastle + "ns");
					if (time_bcastle < time_def) {
						provider = BC;
						c = bcastle_cipher;
					}
				}
				c = Cipher.getInstance(algo, provider);
				c.init(Cipher.ENCRYPT_MODE, k, IV);
				c.doFinal(plaintext);
//				Logger.normal(Rijndael.class, "Using JCA: provider "+provider);
				System.out.println("Using JCA cipher provider: "+provider);
			} catch(GeneralSecurityException e) {
				// ignore
				Logger.warning(clazz, algo + "@" + BC + " benchmark failed", e);
			} catch(Throwable e) {
				// ignore
				Logger.error(clazz, algo + "@" + BC + " benchmark failed", e);
			}
			

			aesCTRProvider = provider;
		}catch (GeneralSecurityException e) {
////		Logger.warning(Rijndael.class, "Not using JCA as it is crippled (can't use 256-bit keys). Will use built-in encryption. ", e);
		}
		
		//KeyGen benchmarks
		algo = preferredKeyGen;
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);
			KeyPairGenerator nss_kpg = null;
			KeyPairGenerator bc_kpg = null;
			
			KeyFactory kf = KeyFactory.getInstance(algo);
			KeyFactory nss_kf = null;
			KeyFactory bc_kf = null;

			ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
			
			long time_def = Long.MAX_VALUE;
			long time_sun = Long.MAX_VALUE;
			long time_nss = Long.MAX_VALUE;
			long time_bc = Long.MAX_VALUE;

			kpg.initialize(spec);
			time_def = keyFactoryBenchmark(kpg, kf);
			System.out.println(algo + " (" + kpg.getProvider() + "): " + time_def + "ns");
			Logger.minor(clazz, algo + "/" + kpg.getProvider() + ": " + time_def + "ns");

			if(NSS != null && kpg.getProvider() != NSS){
				try{
					nss_kpg = KeyPairGenerator.getInstance(algo, NSS);
					nss_kpg.initialize(spec);
					nss_kf = KeyFactory.getInstance(algo, NSS);
					time_nss = keyFactoryBenchmark(nss_kpg, nss_kf);
					System.out.println(algo + " (" + nss_kpg.getProvider() + "): " + time_nss + "ns");
					Logger.minor(clazz, algo + "/" + nss_kpg.getProvider() + ": " + time_nss + "ns");
				} catch(GeneralSecurityException e) {
					e.printStackTrace();
					Logger.warning(clazz, algo + "@" + NSS + " benchmark failed", e);
					// ignore
				}
			}

			if(BC != null && kpg.getProvider() != BC){
				try{
					bc_kpg = KeyPairGenerator.getInstance(algo, BC);
					bc_kpg.initialize(spec);
					bc_kf = KeyFactory.getInstance(algo, BC);
					time_bc = keyFactoryBenchmark(bc_kpg, bc_kf);
					System.out.println(algo + " (" + bc_kpg.getProvider() + "): " + time_bc + "ns");
					Logger.minor(clazz, algo + "/" + bc_kpg.getProvider() + ": " + time_bc + "ns");
				} catch(GeneralSecurityException e) {
					Logger.warning(clazz, algo + "@" + BC + " benchmark failed", e);
					// ignore
				}
			}

			keyGenProvider = fastest(time_def, kpg.getProvider(), time_sun, time_nss, time_bc);
			System.out.println("KeyGen " + algo + ": using " + keyGenProvider);
			Logger.normal(clazz, "KeyGen " + algo + ": using " + keyGenProvider);
		} catch(GeneralSecurityException e){
			throw new Error(e);
		}
		
		//Signature benchmarks
		HashMap<String,Provider> sigProviders_internal = new HashMap<String, Provider>();
		for (SigType sigAlgo: new SigType[] {
				SigType.ECDSAP256//, SigType.ECDSAP384, SigType.ECDSAP512
		}) {;
			algo = sigAlgo.algName;
			try {
				Signature sig = Signature.getInstance(algo);
				Signature nss_sig = null;
				Signature bc_sig = null;

				long time_def = Long.MAX_VALUE;
				long time_sun = Long.MAX_VALUE;
				long time_nss = Long.MAX_VALUE;
				long time_bc = Long.MAX_VALUE;

				time_def = signatureBenchmark(sig, sigAlgo);
				System.out.println(algo + " (" + sig.getProvider() + "): " + time_def + "ns");
				Logger.minor(clazz, algo + "/" + sig.getProvider() + ": " + time_def + "ns");

				if(NSS != null && sig.getProvider() != NSS){
					try{
						nss_sig = Signature.getInstance(algo, NSS);
						time_nss = signatureBenchmark(nss_sig, sigAlgo);
						System.out.println(algo + " (" + nss_sig.getProvider() + "): " + time_nss + "ns");
						Logger.minor(clazz, algo + "/" + nss_sig.getProvider() + ": " + time_nss + "ns");
					} catch(GeneralSecurityException e) {
						e.printStackTrace();
						Logger.warning(clazz, algo + "@" + NSS + " benchmark failed", e);
						// ignore
					}
				}

				if(BC != null && sig.getProvider() != BC){
					try{
						bc_sig = Signature.getInstance(algo, BC);
						time_bc = signatureBenchmark(bc_sig, sigAlgo);
						System.out.println(algo + " (" + bc_sig.getProvider() + "): " + time_bc + "ns");
						Logger.minor(clazz, algo + "/" + bc_sig.getProvider() + ": " + time_bc + "ns");
					} catch(GeneralSecurityException e) {
						Logger.warning(clazz, algo + "@" + BC + " benchmark failed", e);
						// ignore
					}
				}
				Provider fastestSig = fastest(time_def, sig.getProvider(), time_sun, time_nss, time_bc);
				System.out.println(algo + ": using " + fastestSig);
				Logger.normal(clazz, algo + ": using " + fastestSig);

				sigProviders_internal.put(algo, fastestSig);
			} catch(GeneralSecurityException e){
				throw new Error(e);
			}
		}
		sigProviders = Collections.unmodifiableMap(sigProviders_internal);
		
		System.out.println("End of PreferredAlgs");
	}
}