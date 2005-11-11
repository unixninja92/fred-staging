package freenet.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.onionnetworks.fec.DefaultFECCodeFactory;
import com.onionnetworks.fec.FECCode;
import com.onionnetworks.util.Buffer;

import freenet.support.Bucket;
import freenet.support.BucketFactory;
import freenet.support.LRUHashtable;
import freenet.support.Logger;

/**
 * FECCodec implementation using the onion code.
 */
public class StandardOnionFECCodec extends FECCodec {

	// REDFLAG: How big is one of these?
	private static int MAX_CACHED_CODECS = 16;
	// REDFLAG: Optimal stripe size? Smaller => less memory usage, but more JNI overhead
	private static int STRIPE_SIZE = 4096;
	// REDFLAG: Make this configurable, maybe make it depend on # CPUs
	private static int PARALLEL_DECODES = 1;
	
	private static class MyKey {
		/** Number of input blocks */
		int k;
		/** Number of output blocks, including input blocks */
		int n;
		
		public MyKey(int n, int k) {
			this.n = n;
			this.k = k;
		}
		
		public boolean equals(Object o) {
			if(o instanceof MyKey) {
				MyKey key = (MyKey)o;
				return key.n == n && key.k == k;
			} else return false;
		}
		
		public int hashCode() {
			return (n << 16) + k;
		}
	}

	private static LRUHashtable recentlyUsedCodecs = new LRUHashtable();
	
	public synchronized static FECCodec getInstance(int dataBlocks, int checkBlocks) {
		MyKey key = new MyKey(dataBlocks, checkBlocks + dataBlocks);
		StandardOnionFECCodec codec = (StandardOnionFECCodec) recentlyUsedCodecs.get(key);
		if(codec != null) {
			recentlyUsedCodecs.push(key, codec);
			return codec;
		}
		codec = new StandardOnionFECCodec(dataBlocks, checkBlocks + dataBlocks);
		recentlyUsedCodecs.push(key, codec);
		while(recentlyUsedCodecs.size() > MAX_CACHED_CODECS) {
			recentlyUsedCodecs.popKey();
		}
		return codec;
	}

	private final FECCode code;

	private final int k;
	private final int n;
	
	public StandardOnionFECCodec(int k, int n) {
		this.k = k;
		this.n = n;
		code = DefaultFECCodeFactory.getDefault().createFECCode(k,n);
	}

	private static Object runningDecodesSync = new Object();
	private static int runningDecodes;
	
	public void decode(SplitfileBlock[] dataBlockStatus, SplitfileBlock[] checkBlockStatus, int blockLength, BucketFactory bf) throws IOException {
		// Ensure that there are only K simultaneous running decodes.
		synchronized(runningDecodesSync) {
			while(runningDecodes >= PARALLEL_DECODES) {
				try {
					wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
			runningDecodes++;
		}
		try {
			realDecode(dataBlockStatus, checkBlockStatus, blockLength, bf);
		} finally {
			synchronized(runningDecodesSync) {
				runningDecodes--;
			}
		}
	}
	
	public void realDecode(SplitfileBlock[] dataBlockStatus, SplitfileBlock[] checkBlockStatus, int blockLength, BucketFactory bf) throws IOException {
		Logger.minor(this, "Doing decode: "+dataBlockStatus.length+" data blocks, "+checkBlockStatus.length+" check blocks, block length "+blockLength+" with "+this);
		if(dataBlockStatus.length + checkBlockStatus.length != n)
			throw new IllegalArgumentException();
		if(dataBlockStatus.length != k)
			throw new IllegalArgumentException();
		Buffer[] packets = new Buffer[k];
		Bucket[] buckets = new Bucket[n];
		DataInputStream[] readers = new DataInputStream[k];
		OutputStream[] writers = new OutputStream[k];
		int[] toDecode = new int[n-k];
		int numberToDecode = 0; // can be less than n-k
		
		byte[] realBuffer = new byte[n * STRIPE_SIZE];
		
		for(int i=0;i<n;i++)
			packets[i] = new Buffer(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
		
		for(int i=0;i<dataBlockStatus.length;i++) {
			buckets[i] = dataBlockStatus[i].getData();
			if(buckets[i] == null) {
				buckets[i] = bf.makeBucket(blockLength);
				writers[i] = buckets[i].getOutputStream();
				readers[i] = null;
				toDecode[numberToDecode++] = i;
			} else {
				writers[i] = null;
				readers[i] = new DataInputStream(buckets[i].getInputStream());
			}
		}
		for(int i=0;i<checkBlockStatus.length;i++) {
			buckets[i+k] = checkBlockStatus[i].getData();
			if(buckets[i+k] == null) {
				buckets[i+k] = bf.makeBucket(blockLength);
				writers[i+k] = buckets[i+k].getOutputStream();
				readers[i+k] = null;
				toDecode[numberToDecode++] = i+k;
			} else {
				writers[i+k] = null;
				readers[i+k] = new DataInputStream(buckets[i+k].getInputStream());
			}
		}
		
		if(numberToDecode != toDecode.length) {
			int[] newToDecode = new int[numberToDecode];
			System.arraycopy(toDecode, 0, newToDecode, 0, numberToDecode);
			toDecode = newToDecode;
		}

		if(numberToDecode > 0) {
			// Do the (striped) decode
			for(int offset=0;offset<blockLength;offset+=STRIPE_SIZE) {
				// Read the data in first
				for(int i=0;i<n;i++) {
					if(readers[i] != null) {
						readers[i].readFully(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
					}
				}
				// Do the decode
				// Not shuffled
				code.decode(packets, toDecode);
				// packets now contains an array of decoded blocks, in order
				// Write the data out
				for(int i=0;i<n;i++) {
					if(writers[i] != null)
						writers[i].write(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
				}
			}
		}
		for(int i=0;i<n;i++) {
			if(writers[i] != null) writers[i].close();
			if(readers[i] != null) readers[i].close();
		}
		// Set new buckets only after have a successful decode.
		for(int i=0;i<dataBlockStatus.length;i++) {
			dataBlockStatus[i].setData(buckets[i]);
		}
		for(int i=0;i<checkBlockStatus.length;i++) {
			checkBlockStatus[i].setData(buckets[i+k]);
		}
	}

	public void encode(SplitfileBlock[] dataBlockStatus, SplitfileBlock[] checkBlockStatus, int blockLength, BucketFactory bf) throws IOException {
		// Encodes count as decodes.
		synchronized(runningDecodesSync) {
			while(runningDecodes >= PARALLEL_DECODES) {
				try {
					wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
			runningDecodes++;
		}
		try {
			realEncode(dataBlockStatus, checkBlockStatus, blockLength, bf);
		} finally {
			synchronized(runningDecodesSync) {
				runningDecodes--;
			}
		}
	}

	/**
	 * Do the actual encode.
	 */
	private void realEncode(SplitfileBlock[] dataBlockStatus, SplitfileBlock[] checkBlockStatus, int blockLength, BucketFactory bf) throws IOException {
		Logger.minor(this, "Doing encode: "+dataBlockStatus.length+" data blocks, "+checkBlockStatus.length+" check blocks, block length "+blockLength+" with "+this);
		if(dataBlockStatus.length + checkBlockStatus.length != n)
			throw new IllegalArgumentException();
		if(dataBlockStatus.length != k)
			throw new IllegalArgumentException();
		Buffer[] dataPackets = new Buffer[k];
		Buffer[] checkPackets = new Buffer[n-k];
		Bucket[] buckets = new Bucket[n];
		DataInputStream[] readers = new DataInputStream[k];
		OutputStream[] writers = new OutputStream[n-k];
		int[] toEncode = new int[n-k];
		int numberToEncode = 0; // can be less than n-k
		
		byte[] realBuffer = new byte[n * STRIPE_SIZE];

		for(int i=0;i<k;i++)
			dataPackets[i] = new Buffer(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
		for(int i=0;i<n-k;i++)
			checkPackets[i] = new Buffer(realBuffer, (i+k)*STRIPE_SIZE, STRIPE_SIZE);

		for(int i=0;i<dataBlockStatus.length;i++) {
			buckets[i] = dataBlockStatus[i].getData();
			readers[i] = new DataInputStream(buckets[i].getInputStream());
		}
		for(int i=0;i<checkBlockStatus.length;i++) {
			buckets[i+k] = checkBlockStatus[i].getData();
			if(buckets[i+k] == null) {
				buckets[i+k] = bf.makeBucket(blockLength);
				writers[i+k] = buckets[i+k].getOutputStream();
				readers[i+k] = null;
				toEncode[numberToEncode++] = i+k;
			} else {
				writers[i+k] = null;
				readers[i+k] = new DataInputStream(buckets[i+k].getInputStream());
			}
		}
		
		if(numberToEncode > 0) {
			// Do the (striped) decode
			for(int offset=0;offset<blockLength;offset+=STRIPE_SIZE) {
				// Read the data in first
				for(int i=0;i<n;i++) {
					readers[i].readFully(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
				}
				// Do the encode
				// Not shuffled
				code.encode(dataPackets, checkPackets, toEncode);
				// packets now contains an array of decoded blocks, in order
				// Write the data out
				for(int i=k;i<n;i++) {
					if(writers[i] != null)
						writers[i].write(realBuffer, i*STRIPE_SIZE, STRIPE_SIZE);
				}
			}
		}
		for(int i=0;i<k;i++)
			if(readers[i] != null) readers[i].close();
		for(int i=0;i<n-k;i++)
			if(writers[i] != null) writers[i].close();
		// Set new buckets only after have a successful decode.
		for(int i=0;i<checkBlockStatus.length;i++) {
			checkBlockStatus[i].setData(buckets[i+k]);
		}
	}

	public int countCheckBlocks() {
		return n-k;
	}
}
