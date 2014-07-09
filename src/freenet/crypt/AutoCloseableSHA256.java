/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import freenet.support.Logger;

public class AutoCloseableSHA256 extends MessageDigest implements AutoCloseable{
	MessageDigest sha256;
	
	protected AutoCloseableSHA256(Provider provider) {
		super("SHA256");
		try {
			sha256 = MessageDigest.getInstance("SHA256", provider);
		} catch (NoSuchAlgorithmException e) {
			Logger.error(HashType.class, "Internal error; please report:", e);
		}
	}

	/**
	 * Recycles the digest
	 */
	@Override
	public void close() throws Exception {
		SHA256.returnMessageDigest(sha256);
	}

	@Override
	protected byte[] engineDigest() {
		return sha256.digest();
	}

	@Override
	protected void engineReset() {
		sha256.reset();
	}

	@Override
	protected void engineUpdate(byte input) {
		sha256.update(input);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		sha256.update(input, offset, len);
	}

}
