/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class HashTest extends TestCase {
	static private byte[] abc = { (byte)0x61, (byte)0x62, (byte)0x63 };
	static private HashMap<HashType, String> abcVectors = new HashMap<HashType, String>();
	
	@Override
	protected void setUp() throws Exception{
		super.setUp();
		abcVectors.put(HashType.MD5, "900150983cd24fb0d6963f7d28e17f72");
		abcVectors.put(HashType.SHA1, "a9993e364706816aba3e25717850c26c9cd0d89d");
		abcVectors.put(HashType.SHA256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
		abcVectors.put(HashType.SHA384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
		abcVectors.put(HashType.SHA512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	}
	
	//also tests addBytes(byte[]... input) and getHash()
	public void testGetHashByteArrayArray() {
		for(HashType type: abcVectors.keySet()){
			Hash hash = new Hash(type);
			
			//test that output is same as MessageDigest
			byte[] toHash = "This string will test hashing.".getBytes();
			try {
				MessageDigest md = MessageDigest.getInstance(type.javaName);
				byte[] mdResult = md.digest(toHash);
				byte[] hashResult = hash.getHash(toHash);
				boolean expectedResult = true;
				boolean sameHash = MessageDigest.isEqual(mdResult, hashResult);
				assertEquals(expectedResult, sameHash);
			} catch (NoSuchAlgorithmException e) {
				throw new Error("Can't load from any provider."+type.javaName);
			}
			
			//test that output is same as expected
			byte[] abcResult = hash.getHash(abc);
			byte[] expectedABCResult = getABCByteArray(type);
			
			assertTrue(MessageDigest.isEqual(abcResult, expectedABCResult));
			
			//test for null input
			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				hash.getHash(nullArray);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue(throwNull);
			
			//test for null input from a matrix
			boolean throwNulls = false;
			byte[][] nullMatrix = {new byte[4], null};
			try{
				hash.getHash(nullMatrix);
			}catch(NullPointerException e){
				throwNulls = true;
			}
			
			assertTrue(throwNulls);
		}
	}
	
	//tests getHashResult() as well
	public void testGetHashResultHashResultByteArray() {
		for(HashType type: abcVectors.keySet()){
			HashResult hash2 = new HashResult(type, getABCByteArray(type));

			Hash hash = new Hash(type);
			HashResult hash1 = hash.getHashResult(abc);

			assertTrue(Hash.verify(hash1, hash2));
		}
	}
	
	public void testGetHashHex(){
		for(HashType type: abcVectors.keySet()){
			Hash hash = new Hash(type);
			hash.addBytes(abc);
			String hexHash = hash.getHexHash();

			assertEquals(abcVectors.get(type), hexHash);
		}
	}
	
	public void testGetNativeBIgIntegerHashByteArrayArray(){
		for(HashType type: abcVectors.keySet()){
			Hash hash = new Hash(type);
			NativeBigInteger abcVector = new NativeBigInteger(1, getABCByteArray(type));
			NativeBigInteger result = hash.getNativeBigIntegerHash(abc);
			assertEquals(abcVector, result);
		}	
	}
	
	@SuppressWarnings("null")
	public void testAddByteByte(){
		for(HashType type: abcVectors.keySet()){
			byte[] message = "hello world".getBytes();
			Hash hash = new Hash(type);
			byte[] result = hash.getHash(message);

			for (int i = 0; i < message.length; i++)
			{
				hash.addByte(message[i]);
			}
			byte[] result2 = hash.getHash();

			assertTrue(MessageDigest.isEqual(result, result2));	
			
			//test for null input
			boolean throwNull = false;
			Byte nullByte = null;
			try{
				hash.addByte(nullByte);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue(throwNull);
		}
	}
	
	public void testAddBytesByteBuffer(){
		for(HashType type: abcVectors.keySet()){
			byte[] message = "hello world".getBytes();
			ByteBuffer byteBuffer = ByteBuffer.wrap(message);
			
			Hash hash = new Hash(type); 
			byte[] result = hash.getHash(message);
			
			hash.addBytes(byteBuffer);
			byte[] result2 = hash.getHash();
			assertTrue(MessageDigest.isEqual(result, result2));
			
			//test for null input
			boolean throwNull = false;
			ByteBuffer nullBuffer = null;
			try{
				hash.addBytes(nullBuffer);
			}catch(NullPointerException e){
				throwNull = true;
			}
			
			assertTrue(throwNull);
		}
	}
	
	public void testAddByteByteArrayIntInt(){
		for(HashType type: abcVectors.keySet()){
			byte[] message = "hello world".getBytes();
			Hash hash = new Hash(type);
			byte[] result = hash.getHash(message);

			hash.addBytes(message, 0, message.length/2);
			hash.addBytes(message, message.length/2, message.length-message.length/2);
			byte[] result2 = hash.getHash();
			assertTrue(MessageDigest.isEqual(result, result2));	
			
			//test for null input
			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				hash.addBytes(nullArray, 0, message.length);
			}catch(IllegalArgumentException e){
				throwNull = true;
			}
			
			assertTrue(throwNull);
			
			//test for offset out of bounds
			boolean throwOutOfBounds = false;
			try{
				hash.addBytes(message, -3, message.length-3);
			}catch(ArrayIndexOutOfBoundsException e){
				throwOutOfBounds = true;
			}
			
			assertTrue(throwOutOfBounds);
			
			//test for length out of bounds
			throwOutOfBounds = false;
			try{
				hash.addBytes(message, 0, message.length+3);
			}catch(IllegalArgumentException e){
				throwOutOfBounds = true;
			}
			
			assertTrue(throwOutOfBounds);
		}
	}

	public void testVerifyByteArrayByteArray() {
		for(HashType type: abcVectors.keySet()){
			Hash hash = new Hash(type);
			boolean verified = hash.verify(getABCByteArray(type), abc);
			
			assertTrue(verified);
			
			//test for null input1
			boolean throwResult = false;
			byte[] nullResult = null;
			try{
				hash.verify(nullResult, abc);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
			
			//test for null input2
			throwResult = false;
			try{
				hash.verify(abc, nullResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
		}
	}

	public void testVerifyHashResultByteArray() {
		for(HashType type: abcVectors.keySet()){
			byte[] hashResult = getABCByteArray(type);
			HashResult hash1 = new HashResult(type, hashResult);

			assertTrue(Hash.verify(hash1, hashResult));
			
			//test for null input1
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hashResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
			
			//test for null input2
			throwResult = false;
			byte[] nullArray= null;
			try{
				Hash.verify(hash1, nullArray);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
		}
	}
	
	public void testVerifyHashResultHashResult() {
		for(HashType type: abcVectors.keySet()){
			byte[] hashResult = getABCByteArray(type);
			HashResult hash1 = new HashResult(type, hashResult);
			HashResult hash2 = new HashResult(type, hashResult);

			assertTrue(Hash.verify(hash1, hash2));
			
			//test for null input1
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hash2);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
			
			//test for null input2
			throwResult = false;
			try{
				Hash.verify(hash1, nullResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue(throwResult);
		}
	}
	
	private byte[] getABCByteArray(HashType alg){
		return Hex.decode(abcVectors.get(alg));
	}

}
