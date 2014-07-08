/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class HashTest extends TestCase {
	static private byte[] helloWorld = "hello world".getBytes(Charset.forName("UTF-8"));
	static private byte[] nullArray = null;
	static private HashMap<HashType, String> helloWorldTrueVectors = new HashMap<HashType, String>();
	static private HashType[] types;
	
	@Override
	protected void setUp() throws Exception{
		super.setUp();
		
		helloWorldTrueVectors.put(HashType.MD5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
		helloWorldTrueVectors.put(HashType.ED2K, "aa010fbc1d14c795d86ef98c95479d17");
		helloWorldTrueVectors.put(HashType.SHA1, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
		helloWorldTrueVectors.put(HashType.TTH, "ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d");
		helloWorldTrueVectors.put(HashType.SHA256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
		helloWorldTrueVectors.put(HashType.SHA384, "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd");
		helloWorldTrueVectors.put(HashType.SHA512, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
		
		types = new HashType[helloWorldTrueVectors.size()];
		helloWorldTrueVectors.keySet().toArray(types);
	}
	
	
	
	public void testGetHashByteArrayArray() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test that output is same as expected
			byte[] abcResult = hash.getHash(helloWorld);
			byte[] expectedABCResult = getHelloWorldByteArray(type);

			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(abcResult, expectedABCResult));
		}
	}
	
	public void testGetHashByteArrayArrayReset() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test that output is same as expected
			byte[] abcResult = hash.getHash(helloWorld);
			byte[] abcResult2 = hash.getHash(helloWorld);

			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(abcResult, abcResult2));
		}
	}


	//also tests addBytes(byte[]...) and getHash()
	public void testGetHashByteArrayArraySameAsMessageDigest() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test that output is same as MessageDigest
			MessageDigest md = type.get();
			byte[] mdResult = md.digest(helloWorld);
			byte[] hashResult = hash.getHash(helloWorld);
			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(mdResult, hashResult));
		}
	}
	
	public void testGetHashByteArrayArrayNullInput() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			
			//test for null input
			boolean throwNull = false;
			try{
				hash.getHash(nullArray);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue("HashType: "+type.name(), throwNull);
		}
	}
	
	public void testGetHashByteArrayArrayNullMatrixElementInput() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for null input from a matrix
			boolean throwNulls = false;
			byte[][] nullMatrix = {helloWorld, null};
			try{
				hash.getHash(nullMatrix);
			}catch(NullPointerException e){
				throwNulls = true;
			}
			
			assertTrue("HashType: "+type.name(), throwNulls);
		}
	}
	
	//tests getHashResult() as well
	public void testGetHashResultHashResultByteArray() {
		for(HashType type: types){
			HashResult hash2 = new HashResult(type, getHelloWorldByteArray(type));

			Hash hash = new Hash(type);
			HashResult hash1 = hash.getHashResult(helloWorld);

			assertTrue("HashType: "+type.name(), Hash.verify(hash1, hash2));
		}
	}
	
	public void testGetHashHex(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			hash.addBytes(helloWorld);
			String hexHash = hash.getHexHash();

			assertEquals("HashType: "+type.name(), helloWorldTrueVectors.get(type), hexHash);
		}
	}
	
	public void testGetNativeBIgIntegerHashByteArrayArray(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			NativeBigInteger abcVector = new NativeBigInteger(1, getHelloWorldByteArray(type));
			NativeBigInteger result = hash.getNativeBigIntegerHash(helloWorld);
			assertEquals("HashType: "+type.name(), abcVector, result);
		}	
	}
	
	public void testAddByteByte(){
		for(HashType type: types){
			Hash hash = new Hash(type);

			for (int i = 0; i < helloWorld.length; i++){
				hash.addByte(helloWorld[i]);
			}
			
			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(getHelloWorldByteArray(type), hash.getHash()));	
		}
	}
	
	@SuppressWarnings("null")
	public void testAddByteByteNullInput(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for null input
			boolean throwNull = false;
			Byte nullByte = null;
			try{
				hash.addByte(nullByte);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue("HashType: "+type.name(), throwNull);
		}
	}
	
	public void testAddBytesByteBuffer(){
		for(HashType type: types){
			ByteBuffer byteBuffer = ByteBuffer.wrap(helloWorld);
			Hash hash = new Hash(type); 
			
			hash.addBytes(byteBuffer);
			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(getHelloWorldByteArray(type), hash.getHash()));
		}
	}
	
	public void testAddBytesByteBufferNullInput(){
		for(HashType type: types){
			Hash hash = new Hash(type); 
			//test for null input
			boolean throwNull = false;
			ByteBuffer nullBuffer = null;
			try{
				hash.addBytes(nullBuffer);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue("HashType: "+type.name(), throwNull);
		}
	}
	
	public void testAddByteByteArrayIntInt(){
		for(HashType type: types){
			Hash hash = new Hash(type);

			hash.addBytes(helloWorld, 0, helloWorld.length/2);
			hash.addBytes(helloWorld, helloWorld.length/2, helloWorld.length-helloWorld.length/2);
			assertTrue("HashType: "+type.name(), MessageDigest.isEqual(getHelloWorldByteArray(type), hash.getHash()));	
		}
	}
	
	public void testAddByteByteArrayIntIntNullInput(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for null input
			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				hash.addBytes(nullArray, 0, helloWorld.length);
			}catch(IllegalArgumentException e){
				throwNull = true;
			}
			
			assertTrue("HashType: "+type.name(), throwNull);
		}
	}
	
	public void testAddByteByteArrayIntIntOffsetOutOfBounds(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for offset out of bounds
			boolean throwOutOfBounds = false;
			try{
				hash.addBytes(helloWorld, -3, helloWorld.length-3);
			}catch(ArrayIndexOutOfBoundsException e){
				throwOutOfBounds = true;
			}
			
			assertTrue("HashType: "+type.name(), throwOutOfBounds);
		}
	}
	
	public void testAddByteByteArrayIntIntLengthOutOfBounds(){
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for length out of bounds
			boolean throwOutOfBounds = false;
			try{
				hash.addBytes(helloWorld, 0, helloWorld.length+3);
			}catch(IllegalArgumentException e){
				throwOutOfBounds = true;
			}
			
			assertTrue("HashType: "+type.name(), throwOutOfBounds);
		}
	}

	public void testVerifyByteArrayByteArray() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			boolean verified = hash.verify(getHelloWorldByteArray(type), helloWorld);
			
			assertTrue("HashType: "+type.name(), verified);
		}
	}
	
	public void testVerifyByteArrayByteArrayNullInputPos1() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for null input1
			boolean throwResult = false;
			try{
				hash.verify(nullArray, helloWorld);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}
	
	public void testVerifyByteArrayByteArrayNullInputPos2() {
		for(HashType type: types){
			Hash hash = new Hash(type);
			//test for null input2
			boolean throwResult = false;
			try{
				hash.verify(helloWorld, nullArray);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}

	public void testVerifyHashResultByteArray() {
		for(HashType type: types){
			byte[] hashResult = getHelloWorldByteArray(type);
			HashResult hash1 = new HashResult(type, hashResult);

			assertTrue("HashType: "+type.name(), Hash.verify(hash1, hashResult));
		}
	}
	
	public void testVerifyHashResultByteArrayNullInputPos1() {
		for(HashType type: types){
			byte[] hashResult = getHelloWorldByteArray(type);
			//test for null input1
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hashResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}
	
	public void testVerifyHashResultByteArrayNullInputPos2() {
		for(HashType type: types){
			HashResult hash1 = new HashResult(type, getHelloWorldByteArray(type));
			//test for null input2
			boolean throwResult = false;
			try{
				Hash.verify(hash1, nullArray);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}
	
	public void testVerifyHashResultHashResult() {
		for(HashType type: types){
			HashResult hash = new HashResult(type, getHelloWorldByteArray(type));

			assertTrue("HashType: "+type.name(), Hash.verify(hash, hash));
		}
	}
	
	public void testVerifyHashResultHashResultNullInputPos1() {
		for(HashType type: types){
			HashResult hash = new HashResult(type, getHelloWorldByteArray(type));
			//test for null input1
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hash);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}
	
	public void testVerifyHashResultHashResultNullInputPos2() {
		for(HashType type: types){
			HashResult hash = new HashResult(type, getHelloWorldByteArray(type));
			//test for null input2
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(hash, nullResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+type.name(), throwResult);
		}
	}
	
	private byte[] getHelloWorldByteArray(HashType alg){
		return Hex.decode(helloWorldTrueVectors.get(alg));
	}

}
