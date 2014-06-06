/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

public class PreferredAlgorithms{
	// static String preferredSignatureProvider;
	static String preferredSignature = "ECDSA";
	// static String preferredBlockProvider;
	static String preferredBlock = "AES";
	// static String preferredStreamProvider;
	static String preferredStream = "ChaCha";
	static String preferredMesageDigest;

	public static final Map<String, Provider> mdProviders;
	public static final Map<String, Provider> sigProviders;
	public static final Map<String, Provider> blockProviders;
	public static final Map<String, Provider> streamProviders;

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

	static {
		try {
			HashMap<String,Provider> mdProviders_internal = new HashMap<String, Provider>();

			for (String algo: new String[] {
				"SHA1", "MD5", "SHA-256", "SHA-384", "SHA-512"
			}) {
				final Class<?> clazz = Util.class;
				final Provider sun = JceLoader.SUN;
				MessageDigest md = MessageDigest.getInstance(algo);
				md.digest();
				if (sun != null) {
					// SUN provider is faster (in some configurations)
					try {
						MessageDigest sun_md = MessageDigest.getInstance(algo, sun);
						sun_md.digest();
						if (md.getProvider() != sun_md.getProvider()) {
							long time_def = mdBenchmark(md);
							long time_sun = mdBenchmark(sun_md);
							System.out.println(algo + " (" + md.getProvider() + "): " + time_def + "ns");
							System.out.println(algo + " (" + sun_md.getProvider() + "): " + time_sun + "ns");
							Logger.minor(clazz, algo + " (" + md.getProvider() + "): " + time_def + "ns");
							Logger.minor(clazz, algo + " (" + sun_md.getProvider() + "): " + time_sun + "ns");
							if (time_sun < time_def) {
								md = sun_md;
							}
						}
					} catch(GeneralSecurityException e) {
						// ignore
						Logger.warning(clazz, algo + "@" + sun + " benchmark failed", e);
					} catch(Throwable e) {
						// ignore
						Logger.error(clazz, algo + "@" + sun + " benchmark failed", e);
					}
				}
				Provider mdProvider = md.getProvider();
				System.out.println(algo + ": using " + mdProvider);
				Logger.normal(clazz, algo + ": using " + mdProvider);
				mdProviders_internal.put(algo, mdProvider);
			}
			mdProviders = Collections.unmodifiableMap(mdProviders_internal);

			ctx = MessageDigest.getInstance("SHA1", mdProviders.get("SHA1"));
			ctx_length = ctx.getDigestLength();
		} catch(NoSuchAlgorithmException e) {
			// impossible
			throw new Error(e);
		}
	}
}