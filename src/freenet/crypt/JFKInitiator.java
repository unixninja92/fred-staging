/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import org.bouncycastle.util.Arrays;

import freenet.node.NodeCrypto;
import freenet.node.PeerNode;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.Logger;

public final class JFKInitiator extends JFKExchange {

    public JFKInitiator(KeyExchType underlying, int nonceSize, PeerNode pn){
        super(underlying, nonceSize, pn);
    }

    public final byte[] genMessage1(boolean hash, boolean unknownInitiator){
        int offset = 0;
        int nonceSize = hash ? hashnI.length: nonceI.length;
        byte[] message1 = new byte[nonceSize+modulusLength
                                   +(unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)];
        System.arraycopy((hash ? hashnI : nonceI), 0, message1, offset, nonceSize);
        offset += nonceSize;
        System.arraycopy(exponentialI, 0, message1, offset, modulusLength);
        return message1;
    }

    public void processMessage2(byte[] nonceR, byte[] exponentialR, byte[] publicKeyR, 
            byte[] locallyExpectedExponentials, byte[] sigR){
        this.nonceR = nonceR;
        this.exponentialR = exponentialR;

        try {
            CryptSignature sig = new CryptSignature(underlyingExch.type.sigType, publicKeyR);
            if(!sig.verifyData(sigR, locallyExpectedExponentials)){
                Logger.error(this, "The signature verification has failed in JFK(2)!! "+
                        peer.getPeer());
                if(logDEBUG) Logger.debug(this, "Expected signature on "+
                        HexUtil.bytesToHex(exponentialR)+
                        " with "+HexUtil.bytesToHex(publicKeyR)+
                        " signature "+HexUtil.bytesToHex(sigR));
                return;
            }
        } catch (GeneralSecurityException e) {
            Logger.error(JFKInitiator.class, "Internal error; please report:", e);
        } catch (CryptFormatException e) {
            Logger.error(JFKInitiator.class, "Internal error; please report:", e);
        }
    }

    public byte[] genMessage3(byte[] sig, long trackerID, long bootID, byte[] ref, 
            byte[] authenticator){
        int blockSize = CryptBitSetType.RijndaelPCFB.blockSize;
        int ivSize = blockSize >> 3;

        byte[] data = new byte[8 + 8 + ref.length];
        int ptr = 0;
        System.arraycopy(Fields.longToBytes(trackerID), 0, data, ptr, 8);
        ptr += 8;
        if(logMINOR) Logger.minor(this, "Sending tracker ID "+trackerID+" in JFK(3)");
        System.arraycopy(Fields.longToBytes(bootID), 0, data, ptr, 8);
        ptr += 8;
        System.arraycopy(ref, 0, data, ptr, ref.length);
        final byte[] message3 = new byte[nonceI.length*2 + // nI, nR
                                         modulusLength*2 + // g^i, g^r
                                         hashnI.length + // authenticator
                                         hashnI.length + // HMAC(cyphertext)
                                         ivSize + // IV
                                         sig.length + // Signature
                                         data.length]; // The bootid+noderef'

        int offset = 0;
        // Ni
        System.arraycopy(nonceI, 0, message3, offset, nonceI.length);
        offset += nonceI.length;
        if(logDEBUG) Logger.debug(this, "We are sending Ni : " + HexUtil.bytesToHex(nonceI));
        // Nr
        System.arraycopy(nonceR, 0, message3, offset, nonceR.length);
        offset += nonceR.length;
        // g^i
        System.arraycopy(exponentialI, 0,message3, offset, exponentialI.length);
        offset += exponentialI.length;
        // g^r
        System.arraycopy(exponentialR, 0,message3, offset, exponentialR.length);
        offset += exponentialR.length;

        // Authenticator
        System.arraycopy(authenticator, 0, message3, offset, authenticator.length);
        offset += authenticator.length;

        byte[] computedExponential = null;
        try {
            computedExponential = getSharedSecrect(exponentialR);
        } catch (InvalidKeyException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }


        outgoingKey = getSharedSecrect(computedExponential, "0");
        incommingKey = getSharedSecrect(computedExponential, "7");
        jfkKe = getSharedSecrect(computedExponential, "1");
        jfkKa = getSharedSecrect(computedExponential, "2");

        hmacKey = getSharedSecrect(computedExponential, "3");
        ivKey = getSharedSecrect(computedExponential, "4");
        ivNonce = getSharedSecrect(computedExponential, "5");

        byte[] sharedData = getSharedSecrect(computedExponential, "6");
        Arrays.fill(computedExponential, (byte)0);
        ourInitialSeqNum = ((sharedData[0] & 0xFF) << 24)
                | ((sharedData[1] & 0xFF) << 16)
                | ((sharedData[2] & 0xFF) << 8)
                | (sharedData[3] & 0xFF);
        theirInitialSeqNum = ((sharedData[4] & 0xFF) << 24)
                | ((sharedData[5] & 0xFF) << 16)
                | ((sharedData[6] & 0xFF) << 8)
                | (sharedData[7] & 0xFF);

        ourInitialMsgID = ((sharedData[8] & 0xFF) << 24)
                | ((sharedData[9] & 0xFF) << 16)
                | ((sharedData[10] & 0xFF) << 8)
                | (sharedData[11] & 0xFF);
        theirInitialMsgID = ((sharedData[12] & 0xFF) << 24)
                | ((sharedData[13] & 0xFF) << 16)
                | ((sharedData[14] & 0xFF) << 8)
                | (sharedData[15] & 0xFF);

        byte[] iv = KeyGenUtils.genIV(ivSize).getIV();

        int cleartextOffset = 0;
        byte[] cleartext = new byte[JFK_PREFIX_INITIATOR.length + ivSize + sig.length + 
                                    data.length];
        System.arraycopy(JFK_PREFIX_INITIATOR, 0, cleartext, cleartextOffset, 
                JFK_PREFIX_INITIATOR.length);
        cleartextOffset += JFK_PREFIX_INITIATOR.length;
        System.arraycopy(iv, 0, cleartext, cleartextOffset, ivSize);
        cleartextOffset += ivSize;
        System.arraycopy(sig, 0, cleartext, cleartextOffset, sig.length);
        cleartextOffset += sig.length;
        System.arraycopy(data, 0, cleartext, cleartextOffset, data.length);
        cleartextOffset += data.length;

        int cleartextToEncypherOffset = JFK_PREFIX_INITIATOR.length + ivSize;

        CryptBitSet cryptBits = null;
        try {
            cryptBits = new CryptBitSet(CryptBitSetType.RijndaelPCFB, jfkKe, iv);
        } catch (UnsupportedTypeException | InvalidKeyException | 
                InvalidAlgorithmParameterException e) {
            Logger.error(JFKInitiator.class, "Internal error; please report:", e);
        }
        byte[] ciphertext = cryptBits.encrypt(cleartext, cleartextToEncypherOffset, 
                cleartext.length-cleartextToEncypherOffset).array();

        // We compute the HMAC of (prefix + cyphertext) Includes the IV!
        try {
            mac = new MessageAuthCode(MACType.HMACSHA256, jfkKa);
        } catch (InvalidKeyException e) {
            Logger.error(JFKInitiator.class, "Internal error; please report:", e);
        }
        byte[] hmac = mac.genMac(ciphertext).array();

        // copy stuffs back to the message
        System.arraycopy(hmac, 0, message3, offset, hmac.length);
        offset += hmac.length;
        System.arraycopy(iv, 0, message3, offset, ivSize);
        offset += ivSize;
        System.arraycopy(ciphertext, cleartextToEncypherOffset, message3, offset, 
                ciphertext.length-cleartextToEncypherOffset);

        return message3;
    }

    public byte[] processesMessage4(byte[] payload, int inputOffset, byte[] hmac){
        int ivLength = CryptBitSetType.RijndaelPCFB.blockSize >>3;
                int encypheredPayloadOffset = 0;
                // We compute the HMAC of ("R"+cyphertext) : the cyphertext includes the IV!
                byte[] encypheredPayload = Arrays.copyOf(JFK_PREFIX_RESPONDER, 
                        JFK_PREFIX_RESPONDER.length + payload.length - inputOffset);
                encypheredPayloadOffset += JFK_PREFIX_RESPONDER.length;
                System.arraycopy(payload, inputOffset, encypheredPayload, encypheredPayloadOffset, 
                        payload.length-inputOffset);

                if(!mac.verifyData(hmac, encypheredPayload)) {
                    Logger.normal(this, "The digest-HMAC doesn't match; let's discard the packet - "
                            +peer.getPeer());
                    return null;
                }

                CryptBitSet cryptBits = null;
                try {
                    cryptBits = new CryptBitSet(CryptBitSetType.RijndaelPCFB, jfkKe, 
                            encypheredPayload, encypheredPayloadOffset);
                } catch (UnsupportedTypeException | InvalidKeyException | 
                        InvalidAlgorithmParameterException e) {
                    Logger.error(JFKInitiator.class, "Internal error; please report:", e);
                }
                encypheredPayloadOffset += ivLength;

                byte[] decypheredPayload = cryptBits.decrypt(encypheredPayload, 
                        encypheredPayloadOffset, 
                        encypheredPayload.length - encypheredPayloadOffset).array();
                int decypheredPayloadOffset = 0;

                return decypheredPayload;
    }
}
