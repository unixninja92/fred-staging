package freenet.crypt;

import static org.junit.Assert.*;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import freenet.node.NodeStarter;

public class CryptSignatureTest {
	private static final SigType dsaType = SigType.DSA;
	private static final DSAPrivateKey dsaPrivK = new DSAPrivateKey(Global.DSAgroupBigA, NodeStarter.getGlobalSecureRandom());
	private static final DSAPublicKey dsaPubK = new DSAPublicKey(Global.DSAgroupBigA, dsaPrivK);
	
	private static final SigType[] ecdsaTypes = {SigType.ECDSAP256, SigType.ECDSAP384, SigType.ECDSAP512};
	private static final byte[][] publicKeys = 
		{ Hex.decode("3059301306072a8648ce3d020106082a8648ce3d0301070342000489865a155b5c1a73c875274b6b290325fcee9ddbb2db18ddfa3bc3c3c74ad59e2d98017041856f0835338de51bf11c4ec354f05c7ad529c0f86ed0accf5e318f"),
		  Hex.decode("3076301006072a8648ce3d020106052b8104002203620004ff548eba3d7cb70665adf0ea9eaa91fcd6f18202ee21e3130fab138c02e73f907896f250e3ca6c1f235ba8b5cdea57058958bceb1da141c40e4dd23f466766b5f18c96bafcc10a1eed0818e8e41f2170dbe9600d3634f43f60d16f4bea6c9eb9"),
		  Hex.decode("30819b301006072a8648ce3d020106052b810400230381860004010a2770d3182a7504fc4f8b9f8a1fe2f8cc093e2590d9eb8321d43063df1590674262c6c9676c462f80ccb48eabf482b935565dd331a4de733b1fd1c2ea32a14f350184d7e868a0b89ee74f9ba55b90bb2de903794dded4b94980cbcab4e66f8d3d3ec90560fb8b93c33e3f78d40f12f362762a7855726a16ff724d18bcb0d469b053e7")
		};
	private static final byte[][] privateKeys =
		{ Hex.decode("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420b37e4c53f2b30dbe20fd1fcf3f4fc6b9f367949bb15ada1901f9d101cbecd91e"),
		  Hex.decode("304e020100301006072a8648ce3d020106052b81040022043730350201010430f34b6cbcda795a8cd0a488249da35e791dfda41f5ca12ef7dc132cf342dce1fb568d5d1dd8c2c12202d73df213224b03"),
		  Hex.decode("3060020100301006072a8648ce3d020106052b81040023044930470201010442019c70f4538856a2eb270a6d99cac7dd0e51e0e56b55dde864291009b6219af0a21be42079481f97df412f288a519766ca600377e8be87931e9d9cf763f0ea86ea98")
		};
	
	private static final byte[] message = Hex.decode("6bc1bee22e409f96e93d7e117393172a"
			+ "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
			+ "f69f2445df4f9b17ad2b417be66c3710");
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void testCryptSignatureSigTypeKeyPair() {
		fail("Not yet implemented");
	}

	@Test
	public void testCryptSignatureSigTypePublicKeyPrivateKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testCryptSignatureDSAPrivateKeyDSAPublicKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddByteToSign() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToSignByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToSignByteArrayIntInt() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToSignByteBuffer() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddByteToVerify() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToVerifyByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToVerifyByteArrayIntInt() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddBytesToVerifyByteBuffer() {
		fail("Not yet implemented");
	}

	@Test
	public void testSign() {
		CryptSignature sign = new CryptSignature(dsaType);
		assertNotNull("SigType: "+dsaType.name(), sign.sign(message));
		for(SigType type: ecdsaTypes){
			sign = new CryptSignature(type);
			assertNotNull("SigType: "+type.name(), sign.sign(message));
		}
	}
	
	@Test
	public void testSignLength() {
		for(SigType type: ecdsaTypes){
			CryptSignature sign = new CryptSignature(type);
			assertTrue("SigType: "+type.name(), sign.sign(message).length <= type.maxSigSize);
		}
	}

	@Test
	public void testSignByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testSignToDSASignatureByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testSignToDSASignatureBigInteger() {
		fail("Not yet implemented");
	}

	@Test
	public void testSignToNetworkFormat() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyByteArrayIntInt() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyByteArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyByteArrayByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyDSASignatureBigInteger() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyBigIntegerBigIntegerBigInteger() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyDSASignatureByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyBigIntegerBigIntegerByteArrayArray() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetPublicKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testAsFieldSet() {
		fail("Not yet implemented");
	}

}
