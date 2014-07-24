package freenet.crypt;

import java.math.BigInteger;
import java.security.Security;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.framework.TestCase;

public class CryptSignatureTest extends TestCase {
	private static final SigType[] types = SigType.values();
	/*-------------FIPS-EXAMPLE-CONSTANTS---------------------------------------
     * These are the values as they appear in the Appendix 5
     * "Example of the DSA" of FIPS PUB 186-2.
     * We can consider them sure examples */
    private static final BigInteger FIPS_P = new NativeBigInteger(
                                "8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7"+
                                "cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac"+
                                "49693dfbf83724c2ec0736ee31c80291",16);
    private static final BigInteger FIPS_Q = new NativeBigInteger(
                                "c773218c737ec8ee993b4f2ded30f48edace915f",16);
    private static final BigInteger FIPS_G = new NativeBigInteger(
                                "626d027839ea0a13413163a55b4cb500299d5522956cefcb"+
                                "3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9c"+
                                "c42e9f6f464b088cc572af53e6d78802",16);
    private static final BigInteger FIPS_X = new NativeBigInteger(
                                "2070b3223dba372fde1c0ffc7b2e3b498b260614",16);
    private static final BigInteger FIPS_Y = new NativeBigInteger(
                                "19131871d75b1612a819f29d78d1b0d7346f7aa77bb62a85"+
                                "9bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74"+
                                "858fba33f44c06699630a76b030ee333",16);
    private static final BigInteger FIPS_K = new NativeBigInteger(
                                "358dad571462710f50e254cf1a376b2bdeaadfbf",16);
    private static final BigInteger FIPS_K_INV = new NativeBigInteger(
                                "0d5167298202e49b4116ac104fc3f415ae52f917",16);
    private static final BigInteger FIPS_SHA1_M = new NativeBigInteger(
                                "a9993e364706816aba3e25717850c26c9cd0d89d",16);
    private static final BigInteger FIPS_R = new NativeBigInteger(
                                "8bac1ab66410435cb7181f95b16ab97c92b341c0",16);
    private static final BigInteger FIPS_S = new NativeBigInteger(
                                "41e2345f1f56df2458f426d155b4ba2db6dcd8c8",16);
    private static final DSAGroup FIPS_DSA_GROUP = 
                    new DSAGroup(FIPS_P,FIPS_Q,FIPS_G);
    private static final DSAPrivateKey FIPS_DSA_PRIVATE_KEY = 
                    new DSAPrivateKey(FIPS_X, FIPS_DSA_GROUP);
    private static final DSAPublicKey FIPS_DSA_PUBLIC_KEY =
                    new DSAPublicKey(FIPS_DSA_GROUP,FIPS_Y);
    private static final DSASignature FIPS_DSA_SIGNATURE = 
                    new DSASignature(FIPS_R,FIPS_S);
	static{
		Security.addProvider(new BouncyCastleProvider());
		
	}
	
	public void testAddByte() {
		fail("Not yet implemented");
	}

	public void testAddBytesByteArray() {
		fail("Not yet implemented");
	}

	public void testAddBytesByteArrayIntInt() {
		fail("Not yet implemented");
	}

	public void testAddBytesByteBuffer() {
		fail("Not yet implemented");
	}

	public void testSign() {
		fail("Not yet implemented");
	}
	
	public void testSignByteArray() {
		fail("Not yet implemented");
	}

	public void testSignToDSASignatureByteArrayArray() {
		fail("Not yet implemented");
	}

	public void testSignToDSASignatureBigInteger() {
		fail("Not yet implemented");
	}

	public void testSignToNetworkFormat() {
		fail("Not yet implemented");
	}

	public void testVerifyByteArray() {
		fail("Not yet implemented");
	}

	public void testVerifyByteArrayByteArrayArray() {
		fail("Not yet implemented");
	}

	public void testVerifyDSASignatureBigInteger() {
		fail("Not yet implemented");
	}

	public void testVerifyBigIntegerBigIntegerBigInteger() {
		fail("Not yet implemented");
	}

	public void testVerifyDSASignatureByteArrayArray() {
		fail("Not yet implemented");
	}

	public void testVerifyBigIntegerBigIntegerByteArrayArray() {
		fail("Not yet implemented");
	}

	public void testGetPublicKey() {
		fail("Not yet implemented");
	}

	public void testAsFieldSet() {
		fail("Not yet implemented");
	}

}
