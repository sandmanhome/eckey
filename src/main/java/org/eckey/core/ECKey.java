/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2014-2016 the libsecp256k1 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.eckey.core;

import com.google.common.base.Preconditions;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.*;

public class ECKey {
    public static enum KeyType {
        K1, SM2,
    }

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters K1_CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters SM2_CURVE_PARAMS = CustomNamedCurves.getByName("sm2p256v1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters K1_CURVE;

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters SM2_CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a
     * signature. If you aren't sure what this is about, you can ignore it.
     */
    public static final BigInteger K1_HALF_CURVE_ORDER;

    public static final BigInteger SM2_HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    static {
        // Init proper random number generator, as some old Android installations have
        // bugs that make it unsecure.
        if (Utils.isAndroidRuntime())
            new LinuxSecureRandom();

        K1_CURVE = new ECDomainParameters(K1_CURVE_PARAMS.getCurve(), K1_CURVE_PARAMS.getG(), K1_CURVE_PARAMS.getN(),
                K1_CURVE_PARAMS.getH());
        K1_HALF_CURVE_ORDER = K1_CURVE_PARAMS.getN().shiftRight(1);

        // Tell Bouncy Castle to precompute data that's needed during sm2p256v1
        // calculations.
        // FixedPointUtil 使用 PRECOMP_NAME 限制预算的曲线只能一条，这里默认预算sm2,
        FixedPointUtil.precompute(SM2_CURVE_PARAMS.getG());
        SM2_CURVE = new ECDomainParameters(SM2_CURVE_PARAMS.getCurve(), SM2_CURVE_PARAMS.getG(),
                SM2_CURVE_PARAMS.getN(), SM2_CURVE_PARAMS.getH());
        SM2_HALF_CURVE_ORDER = SM2_CURVE_PARAMS.getN().shiftRight(1);

        secureRandom = new SecureRandom();
    }

    public static String KeyTypeToString(KeyType type) {
        if (type == KeyType.SM2) {
            return "SM2";
        } else if (type == KeyType.K1) {
            return "K1";
        } else {
            throw new UnknownKeyTypeException();
        }
    }

    public static KeyType StringToKeyType(String type) {
        if (type.equals("SM2")) {
            return KeyType.SM2;
        } else if (type.equals("K1")) {
            return KeyType.K1;
        } else {
            throw new UnknownKeyTypeException();
        }
    }

    public static ECDomainParameters GetCURVE(KeyType type) {
        if (type == KeyType.SM2) {
            return SM2_CURVE;
        } else if (type == KeyType.K1) {
            return K1_CURVE;
        } else {
            throw new UnknownKeyTypeException();
        }
    }

    public static BigInteger GetHALFCURVEORDER(KeyType type) {
        if (type == KeyType.SM2) {
            return SM2_HALF_CURVE_ORDER;
        } else if (type == KeyType.K1) {
            return K1_HALF_CURVE_ORDER;
        } else {
            throw new UnknownKeyTypeException();
        }
    }

    // The two parts of the key. If "pub" is set but not "priv", we can only verify
    // signatures, not make them.
    @Nullable
    protected final KeyType type;
    protected final BigInteger priv; // A field element.
    protected final ECPoint pub;
    protected final ECDomainParameters CURVE;

    public ECKey() {
        this(KeyType.SM2);
    }

    public ECKey(KeyType keyType) {
        type = keyType;
        ECKeyGenerationParameters keygenParams;
        if (keyType == KeyType.SM2) {
            CURVE = SM2_CURVE;
            keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        } else {
            CURVE = K1_CURVE;
            keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        }

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keygenParams);

        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        pub = pubParams.getQ();
    }

    private ECKey(KeyType type, ECDomainParameters CURVE, BigInteger priv, ECPoint pub) {
        this.type = type;
        this.CURVE = CURVE;
        this.priv = priv;
        this.pub = pub;
    }

    public static ECKey ECKeyFromPrivate(String str) {
        Map<String, Object> key = StringToKey(str);
        String prefix = (String)key.get("prefix");
        if (!prefix.equals("PVT")) {
            throw new ErrorKeyFormatException();
        }

        byte[] privKeyBytes = (byte[])key.get("payload");
        KeyType type = StringToKeyType((String)key.get("type"));
        ECDomainParameters CURVE = type == KeyType.SM2 ? SM2_CURVE : K1_CURVE;
        BigInteger priv = new BigInteger(1, privKeyBytes);
        ECPoint publicKey = publicPointFromPrivate(priv, CURVE);
        return new ECKey(type, CURVE, priv, publicKey);
    }

    public static String PrivateToPublic(String str) {
        return ECKeyFromPrivate(str).GetPublic();
    }

    private static ECPoint publicPointFromPrivate(BigInteger privKey, ECDomainParameters CURVE) {
        /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than
         * the group order, but that could change in future versions.
         */
        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }
        return new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
    }

    public String GetPrivate() {
        return KeyToString("PVT", KeyTypeToString(type), getPrivKeyBytes());
    }

    public String GetPublic() {
        return KeyToString("PUB", KeyTypeToString(type), getPubKeyBytes());
    }

    public static class MissingPrivateKeyException extends RuntimeException {
    }

    public static class ErrorKeyFormatException extends RuntimeException {
    }

    public static class ErrorChecksumException extends RuntimeException {
    }

    public static class UnknownKeyTypeException extends RuntimeException {
    }

    private BigInteger getPrivKey() {
        if (priv == null)
            throw new MissingPrivateKeyException();
        return priv;
    }

    private byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(getPrivKey(), 32);
    }

    private byte[] getPubKeyBytes() {
        return pub.getEncoded(true);
    }

    private static String KeyToString(String prefix, String type, byte[] payload) {
        byte[] bits = new byte[payload.length + type.length()];
        System.arraycopy(payload, 0, bits, 0, payload.length);
        System.arraycopy(type.getBytes(), 0, bits, payload.length, type.length());
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(bits, 0, bits.length);
        byte[] ripmemdHash = new byte[20];
        digest.doFinal(ripmemdHash, 0);

        byte[] output = new byte[payload.length + 4];
        System.arraycopy(payload, 0, output, 0, payload.length);
        System.arraycopy(ripmemdHash, 0, output, payload.length, 4);
        return prefix + "_" + type + "_" + Base58.encode(output);
    }

    public static Map<String, Object> StringToKey(String str) {
        String[] key = str.split("_");
        if (key.length < 3 ) {
            throw new ErrorKeyFormatException();
        }

        String prefix = key[0];
        if (!(prefix.equals("SIG") ||  prefix.equals("PVT") || prefix.equals("PUB"))) {
            throw new ErrorKeyFormatException();
        }
        
        String type = key[1];
        // check keytype
        StringToKeyType(type);

        byte[] raw = Base58.decode(key[2]);
        int length = raw.length - 4;
        byte[] payload = new byte[length];
        System.arraycopy(raw, 0, payload, 0, length);

        byte[] bits = new byte[payload.length + type.length()];
        System.arraycopy(payload, 0, bits, 0, payload.length);
        System.arraycopy(type.getBytes(), 0, bits, payload.length, type.length());

        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(bits, 0, bits.length);
        byte[] ripmemdHash = new byte[20];
        digest.doFinal(ripmemdHash, 0);

        if (!(raw[length] == ripmemdHash[0] && raw[length + 1] == ripmemdHash[1] && raw[length + 2] == ripmemdHash[2]
                && raw[length + 3] == ripmemdHash[3])) {
            throw new ErrorChecksumException();
        }

        Map<String, Object> result = new HashMap<String, Object>();
        result.put("prefix", prefix);
        result.put("type", type);
        result.put("payload", payload);
        return result;
    }

    public String sign(byte[] hash) {
        ECDSASignature sig = doSign(hash, priv);
        assert(sig.isCanonical());
        byte recId = findRecoveryId(hash, sig);
        //int headerByte = recId + 27 + (isCompressed() ? 4 : 0);
        int headerByte = recId + 27;
        byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
        sigData[0] = (byte)headerByte;
        System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
        System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
        return KeyToString("SIG", KeyTypeToString(type), sigData);
    }

    public String sign(String message) {
        byte[] hash = Sha256Hash.hash(message.getBytes());
        return sign(hash);
    }

    public void verifyMessage(String message, String sigStr) throws SignatureException {
        String publicKey = ECKey.signedMessageToKey(message, sigStr);
        if (!publicKey.equals(GetPublic()))
            throw new SignatureException("Signature did not match for message");
    }

    public static String signedMessageToKey(String message, String sigStr) throws SignatureException {
        Map<String, Object> key = StringToKey(sigStr);
        String prefix = (String)key.get("prefix");
        if (!prefix.equals("SIG")) {
            throw new SignatureException("Signature Str, expected SIG and got " + prefix);
        }

        String type = (String)key.get("type");
        byte[] signature = (byte[])key.get("payload");
        if (signature.length < 65)
            throw new SignatureException("Signature truncated, expected 65 bytes and got " + signature.length);
        int header = signature[0] & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34)
            throw new SignatureException("Header byte out of range: " + header);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 1, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 33, 65));

        byte[] hash = Sha256Hash.hash(message.getBytes());
        ECDSASignature sig = new ECDSASignature(r, s, StringToKeyType(type));
        if (header >= 31) {
            header -= 4;
        }
        int recId = header - 27;
        ECPoint publicKey = ECKey.recoverFromSignature(recId, sig, hash);
        if (publicKey == null)
            throw new SignatureException("Could not recover public key from signature");
        
        return KeyToString("PUB", type, publicKey.getEncoded(true));
    }

    protected ECDSASignature doSign(byte[] hash, BigInteger privateKeyForSigning) {
        checkNotNull(privateKeyForSigning);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(hash);
        return new ECDSASignature(components[0], components[1], type).toCanonicalised();
    }

    /**
     * Groups the two components that make up a signature, and provides a way to encode to DER form, which is
     * how ECDSA signatures are represented when embedded in other data structures in the Bitcoin protocol. The raw
     * components can be useful for doing further EC maths on them.
     */
    public static class ECDSASignature {
        /** The two components of the signature. */
        public final BigInteger r, s;

        public final KeyType type;

        public ECDSASignature(BigInteger r, BigInteger s, KeyType type) {
            this.r = r;
            this.s = s;

            this.type = type;
        }
        
        /**
         * Returns true if the S component is "low", that means it is below {@link ECKey#HALF_CURVE_ORDER}. See <a
         * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">BIP62</a>.
         */
        public boolean isCanonical() {
            return s.compareTo(GetHALFCURVEORDER(type)) <= 0;
        }

        /**
         * Will automatically adjust the S component to be less than or equal to half the curve order, if necessary.
         * This is required because for every signature (r,s) the signature (r, -s (mod N)) is a valid signature of
         * the same message. However, we dislike the ability to modify the bits of a Bitcoin transaction after it's
         * been signed, as that violates various assumed invariants. Thus in future only one of those forms will be
         * considered legal and the other will be banned.
         */
        public ECDSASignature toCanonicalised() {
            if (!isCanonical()) {
                // The order of the curve is the number of valid points that exist on that curve. If S is in the upper
                // half of the number of valid points, then bring it back to the lower half. Otherwise, imagine that
                //    N = 10
                //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
                //    10 - 8 == 2, giving us always the latter solution, which is canonical.
                return new ECDSASignature(r, GetCURVE(type).getN().subtract(s), type);
            } else {
                return this;
            }
        }
    }

    /**
     * Returns the recovery ID, a byte with value between 0 and 3, inclusive, that specifies which of 4 possible
     * curve points was used to sign a message. This value is also referred to as "v".
     *
     * @throws RuntimeException if no recovery ID can be found.
     */
    public byte findRecoveryId(byte[] hash, ECDSASignature sig) {
        byte recId = -1;
        for (byte i = 0; i < 4; i++) {
            ECPoint publicKey = ECKey.recoverFromSignature(i, sig, hash);
            if (publicKey != null && publicKey.equals(pub)) {
                recId = i;
                break;
            }
        }
        if (recId == -1)
            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
        return recId;
    }

    @Nullable
    public static ECPoint recoverFromSignature(int recId, ECDSASignature sig, byte[] hash) {
        Preconditions.checkArgument(recId >= 0, "recId must be positive");
        Preconditions.checkArgument(sig.r.signum() >= 0, "r must be positive");
        Preconditions.checkArgument(sig.s.signum() >= 0, "s must be positive");
        Preconditions.checkNotNull(hash);
        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = GetCURVE(sig.type).getN();  // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs "invalid", then
        //        do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime;
        if (sig.type == KeyType.SM2) {
            prime = SM2P256V1Curve.q;
        } else if (sig.type == KeyType.K1) {
            prime = SecP256K1Curve.q;
        } else {
            throw new UnknownKeyTypeException();
        }
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(GetCURVE(sig.type), x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
        if (!R.multiply(n).isInfinity())
            return null;
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, hash);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(GetCURVE(sig.type).getG(), eInvrInv, R, srInv);
        return q;
    }

    /** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
    private static ECPoint decompressKey(ECDomainParameters CURVE, BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }
}
