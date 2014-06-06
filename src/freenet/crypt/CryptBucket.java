package freenet.crypt;

import freenet.support.api.Bucket;

public class CryptBucket implements Bucket {
	public static final byte ALGO_AES_PCFB_256_SHA256 = 2;
    public static final byte ALGO_AES_CTR_256_SHA256 = 3;
    public static final byte ALGO_CHACHA = 4;
	private byte cryptoAlgorithm;
    private boolean readOnly;
}