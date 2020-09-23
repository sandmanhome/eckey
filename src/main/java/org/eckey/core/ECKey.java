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

import com.google.common.primitives.Bytes;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Enumeration;
import java.io.ByteArrayInputStream;

import static com.google.common.base.Preconditions.*;

public class ECKey {
    public static enum KeyType {
        K1, SM2,
    }
    
    /**
     * Index of R value in the signature result of softkey signing
     */
    private static final int R_INDEX = 0;

    /**
     * Index of S value in the signature result of softkey signing
     */
    private static final int S_INDEX = 1;

    /**
     * EC domain parameters of SM2 key
     */
    private static final ECDomainParameters ecParamsSM2;

    /**
     * EC domain parameters of K1 key
     */
    private static final ECDomainParameters ecParamsK1;

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters K1_CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    // The parameters of the sm2p256v1 curve that Bitcoin uses.
    private static final X9ECParameters SM2_CURVE_PARAMS = CustomNamedCurves.getByName("sm2p256v1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters K1_CURVE;

    /** The parameters of the sm2p256v1 curve that Bitcoin uses. */
    public static final ECDomainParameters SM2_CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a
     * signature. If you aren't sure what this is about, you can ignore it.
     */
    public static final BigInteger K1_HALF_CURVE_ORDER;

    public static final BigInteger SM2_HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    //SIGNATURE RELATED CONSTANTS
    private static final int VALUE_TO_ADD_TO_SIGNATURE_HEADER = 31;
    private static final int EXPECTED_R_OR_S_LENGTH = 32;
    private static final int NUMBER_OF_POSSIBLE_PUBLIC_KEYS = 4;

    //CONSTANTS USED DURING EOS DECODING
    // private static final byte UNCOMPRESSED_PUBLIC_KEY_BYTE_INDICATOR = 0x04;
    private static final byte COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y = 0x02;
    private static final byte COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y = 0x03;

    //CHECKSUM RELATED
    private static final String SM2P256V1_CHECKSUM_VALIDATION_SUFFIX = "SM2";
    private static final String SECP256K1_CHECKSUM_VALIDATION_SUFFIX = "K1";

    //CONSTANTS USED DURING DECODING AND CHECKSUM VALIDATION
    private static final int CHECKSUM_BYTES = 4;

    /*
    ICBS Format Prefixes - The prefixes below are all used to preface the ICBS format of certain types
    of keys and signatures.  For instance, 'EOS' is used to preface a legacy form of a public key
    that was generated using the secp256k1 algorithm.  The prefixes and there associated objects are
    as follows:
    SIG_K1_  - Signature signed with key generated with secp256k1 algorithm.
    SIG_SM2_ - Signature signed with key generated with sm2p256v1 algorithm.
     */
    private static final String PATTERN_STRING_EOS_PREFIX_SIG_SM2 = "SIG_SM2_";
    private static final String PATTERN_STRING_EOS_PREFIX_SIG_K1 = "SIG_K1_";

    static {
        // Init proper random number generator, as some old Android installations have
        // bugs that make it unsecure.
        if (Utils.isAndroidRuntime())
            new LinuxSecureRandom();

        X9ECParameters paramsK1 = SECNamedCurves.getByName("secp256k1");
        ecParamsK1 = new ECDomainParameters(paramsK1.getCurve(), paramsK1.getG(), paramsK1.getN(),
                paramsK1.getH());

        X9ECParameters paramsSM2 = GMNamedCurves.getByName("sm2p256v1");
        ecParamsSM2 = new ECDomainParameters(paramsSM2.getCurve(), paramsSM2.getG(),
                paramsSM2.getN(), paramsSM2.getH());

        // Tell Bouncy Castle to precompute data that's needed during sm2p256v1
        // calculations.
        // FixedPointUtil 使用 PRECOMP_NAME 限制预算的曲线只能一条，这里默认预算sm2,
        FixedPointUtil.precompute(K1_CURVE_PARAMS.getG());

        K1_CURVE = new ECDomainParameters(K1_CURVE_PARAMS.getCurve(), K1_CURVE_PARAMS.getG(),
                K1_CURVE_PARAMS.getN(), K1_CURVE_PARAMS.getH());
        K1_HALF_CURVE_ORDER = K1_CURVE_PARAMS.getN().shiftRight(1);

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
    protected final ECDomainParameters CURVEParameters;
    protected final ECPublicKeyParameters publicKeyParameters;
    protected final ECPrivateKeyParameters privateKeyParameters;

    public ECKey() {
        this(KeyType.SM2);
    }

    public ECKey(KeyType keyType) {
        type = keyType;
        ECKeyGenerationParameters keygenParams;
        if (keyType == KeyType.SM2) {
            CURVEParameters = SM2_CURVE;
            keygenParams = new ECKeyGenerationParameters(CURVEParameters, secureRandom);
        } else {
            CURVEParameters = K1_CURVE;
            keygenParams = new ECKeyGenerationParameters(CURVEParameters, secureRandom);
        }

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keygenParams);

        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        privateKeyParameters = (ECPrivateKeyParameters) keypair.getPrivate();
        publicKeyParameters = (ECPublicKeyParameters) keypair.getPublic();
        priv = privateKeyParameters.getD();
        pub = publicKeyParameters.getQ();
    }

    private ECKey(KeyType type, ECDomainParameters CURVEParameters, BigInteger priv) {
        this.type = type;
        this.CURVEParameters = CURVEParameters;

        this.priv = priv;
        this.privateKeyParameters = new ECPrivateKeyParameters(priv, CURVEParameters);

        ECPoint publicKey = publicPointFromPrivate(priv, CURVEParameters);
        this.publicKeyParameters = new ECPublicKeyParameters(publicKey, CURVEParameters);
        this.pub = publicKeyParameters.getQ();
    }

    private ECKey(KeyType type, ECPublicKeyParameters publicKeyParameters,
            ECDomainParameters CURVE) {
        this.type = type;
        this.CURVEParameters = CURVE;
        this.priv = null;
        this.privateKeyParameters = null;
        this.publicKeyParameters = publicKeyParameters;
        this.pub = publicKeyParameters.getQ();
    }

    public static ECKey ECKeyFromPrivate(String str) {
        Map<String, Object> key = StringToKey(str);
        String prefix = (String) key.get("prefix");
        if (!prefix.equals("PVT")) {
            throw new ErrorKeyFormatException();
        }

        byte[] privKeyBytes = (byte[]) key.get("payload");
        KeyType type = StringToKeyType((String) key.get("type"));
        ECDomainParameters CURVEParameters = type == KeyType.SM2 ? SM2_CURVE : K1_CURVE;
        BigInteger priv = new BigInteger(1, privKeyBytes);
        return new ECKey(type, CURVEParameters, priv);
    }

    public static ECKey ECKeyFromPublic(String str) {
        Map<String, Object> key = StringToKey(str);
        String prefix = (String) key.get("prefix");
        if (!prefix.equals("PUB")) {
            throw new ErrorKeyFormatException();
        }

        byte[] pubKeyBytes = (byte[]) key.get("payload");
        KeyType type = StringToKeyType((String) key.get("type"));
        ECPublicKeyParameters publicKeyParameters;
        ECDomainParameters CURVEParameters;
        if (type == KeyType.SM2) {
            CURVEParameters = SM2_CURVE;
            SM2P256V1Curve curve = new SM2P256V1Curve();
            publicKeyParameters =
                    new ECPublicKeyParameters(curve.decodePoint(pubKeyBytes), CURVEParameters);
        } else if (type == KeyType.K1) {
            CURVEParameters = K1_CURVE;
            SecP256K1Curve curve = new SecP256K1Curve();
            publicKeyParameters =
                    new ECPublicKeyParameters(curve.decodePoint(pubKeyBytes), CURVEParameters);
        } else {
            throw new ErrorKeyFormatException();
        }

        return new ECKey(type, publicKeyParameters, CURVEParameters);
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

    public ECPublicKeyParameters GetECPublicKeyParameters() {
        return publicKeyParameters;
    }

    public ECPrivateKeyParameters GetECPrivateKeyParameters() {
        return privateKeyParameters;
    }

    public KeyType GetKeyType() {
        return type;
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

    public static AlgorithmEmployed getAlgorithm(KeyType type) {
        if (type == KeyType.SM2) {
            return AlgorithmEmployed.SM2P256V1;
        } else if (type == KeyType.K1) {
            return AlgorithmEmployed.SECP256K1;
        } else {
            throw new UnknownKeyTypeException();
        }
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
        if (key.length < 3) {
            throw new ErrorKeyFormatException();
        }

        String prefix = key[0];
        if (!(prefix.equals("SIG") || prefix.equals("PVT") || prefix.equals("PUB"))) {
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

        if (!(raw[length] == ripmemdHash[0] && raw[length + 1] == ripmemdHash[1]
                && raw[length + 2] == ripmemdHash[2] && raw[length + 3] == ripmemdHash[3])) {
            throw new ErrorChecksumException();
        }

        Map<String, Object> result = new HashMap<String, Object>();
        result.put("prefix", prefix);
        result.put("type", type);
        result.put("payload", payload);
        return result;
    }

    public String sign(String message) throws Exception {
        return sign(message.getBytes());
    }

    public String sign(byte[] data) throws Exception {
        byte[] hash = Sha256Hash.hash(data);
        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters parameters = GetECPrivateKeyParameters();
        signer.init(true, parameters);
        BigInteger[] signatureComponents = signer.generateSignature(hash);
        return doSign(signatureComponents[R_INDEX].toString(), signatureComponents[S_INDEX].toString(), data);
    }

    public byte[] doSignWithSM3(byte[] data) throws Exception {
        SM2Signer signer = new SM2Signer();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(priv, CURVEParameters);
        ParametersWithID parameters = new ParametersWithID(privKey, "1234567812345678".getBytes());
        signer.init(true, parameters);
        signer.update(data, 0, data.length);
        byte[] sig = decodeDERSignature(signer.generateSignature());
        return sig;
    }

    public Boolean verifySignWithSM3(byte[] msgBytes, byte[] sigBytes) throws Exception {
        // 因为这里传入的是 Hex.decode(PUBLIC_KEY)
        SM2Signer signer = new SM2Signer();
        ParametersWithID parameters =
                new ParametersWithID(publicKeyParameters, "1234567812345678".getBytes());
        signer.init(false, parameters);
        signer.update(msgBytes, 0, msgBytes.length);
        return signer.verifySignature(encodeDERSignature(sigBytes));
    }

    private static byte[] encodeDERSignature(byte[] signature) throws Exception {
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, r)));
        vector.add(new ASN1Integer(new BigInteger(1, s)));

        try {
            return (new DERSequence(vector)).getEncoded();
        } catch (Exception var6) {
            throw new Exception();
        }
    }

    private static byte[] decodeDERSignature(byte[] signature) throws Exception {
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(signature));

        try {
            ASN1Sequence primitive = (ASN1Sequence) stream.readObject();
            Enumeration enumeration = primitive.getObjects();
            BigInteger R = ((ASN1Integer) enumeration.nextElement()).getValue();
            BigInteger S = ((ASN1Integer) enumeration.nextElement()).getValue();
            byte[] bytes = new byte[64];
            byte[] r = format(R.toByteArray());
            byte[] s = format(S.toByteArray());
            System.arraycopy(r, 0, bytes, 0, 32);
            System.arraycopy(s, 0, bytes, 32, 32);
            return bytes;
        } catch (Exception var10) {
            throw new Exception();
        }
    }

    private static byte[] format(byte[] value) {
        if (value.length == 32) {
            return value;
        } else {
            byte[] bytes = new byte[32];
            if (value.length > 32) {
                System.arraycopy(value, value.length - 32, bytes, 0, 32);
            } else {
                System.arraycopy(value, 0, bytes, 32 - value.length, value.length);
            }

            return bytes;
        }
    }

    public void verifyMessage(byte[] data, String sigStr) throws SignatureException {
        String publicKey = ECKey.signedMessageToKey(data, sigStr);
        if (!publicKey.equals(GetPublic()))
            throw new SignatureException("Signature did not match for message");
    }

    public static String signedMessageToKey(byte[] data, String sigStr) throws SignatureException {
        Map<String, Object> key = StringToKey(sigStr);
        String prefix = (String) key.get("prefix");
        if (!prefix.equals("SIG")) {
            throw new SignatureException("Signature Str, expected SIG and got " + prefix);
        }

        String type = (String) key.get("type");
        byte[] signature = (byte[]) key.get("payload");
        if (signature.length < 65)
            throw new SignatureException(
                    "Signature truncated, expected 65 bytes and got " + signature.length);
        int header = signature[0] & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34)
            throw new SignatureException("Header byte out of range: " + header);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 1, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 33, 65));

        if (header >= 31) {
            header -= 4;
        }
        int recId = header - 27;
        byte[] publicKey = ECKey.recoverPublicKeyFromSignature(recId, r, s, Sha256Hash.of(data),
                true, ECKey.getAlgorithm(StringToKeyType(type)));
        if (publicKey == null)
            throw new SignatureException("Could not recover public key from signature");

        return KeyToString("PUB", type, publicKey);
    }

    public boolean isCanonical(BigInteger v) {
        return v.compareTo(GetHALFCURVEORDER(type)) <= 0;
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
     * This method converts a signature to a ICBS compliant form.  The signature to be converted must
     * be an The ECDSA signature that is a DER encoded ASN.1 sequence of two integer fields (see
     * ECDSA-Sig-Value in rfc3279 section 2.2.3).  This method should be used when only the R and S
     * values of the signature are available.
     *
     * The DER encoded ECDSA signature follows the following format: Byte 1 - Sequence (Should be
     * 30) Byte 2 - Signature length Byte 3 - R Marker (0x02) Byte 4 - R length Bytes 5 to 37 or 38-
     * R Byte After R - S Marker (0x02) Byte After S Marker - S Length Bytes After S Length - S
     * (always 32-33 bytes) Byte Final - Hash Type
     *
     * @param signatureR R value as BigInteger in string format
     * @param signatureS S value as BigInteger in string format
     * @param signableTransaction Transaction in signable format
     * @return ICBS format of signature
     * @throws Exception if conversion to ICBS format fails.
     */
    public String doSign(String signatureR, String signatureS,
            byte[] signableTransaction) throws Exception {
        String icbsFormattedSignature = "";

        try {
            AlgorithmEmployed algorithmEmployed = getAlgorithm(type);
            byte[] keyData = getPubKeyBytes();

            BigInteger r = new BigInteger(signatureR);
            BigInteger s = new BigInteger(signatureS);

            s = checkAndHandleLowS(s, algorithmEmployed);

            /*
            Get recovery ID.  This is the index of the public key (0-3) that represents the
            expected public key used to sign the transaction.
             */
            int recoverId = getRecoveryId(r, s, Sha256Hash.of(signableTransaction), keyData,
                    algorithmEmployed);

            if (recoverId < 0) {
                throw new Exception("Could not recover public key from Signature.");
            }

            //Add RecoveryID + 27 + 4 to create the header byte
            recoverId += VALUE_TO_ADD_TO_SIGNATURE_HEADER;
            byte headerByte = ((Integer) recoverId).byteValue();

            byte[] decodedSignature = Bytes.concat(new byte[] {headerByte},
                    Utils.bigIntegerToBytes(r, EXPECTED_R_OR_S_LENGTH),
                    Utils.bigIntegerToBytes(s, EXPECTED_R_OR_S_LENGTH));
            if (algorithmEmployed.equals(AlgorithmEmployed.SECP256K1)
                    && !isCanonical(decodedSignature)) {
                throw new Exception("Input signature is not canonical.");
            }

            //Add checksum to signature
            byte[] signatureWithCheckSum;
            String signaturePrefix;
            switch (algorithmEmployed) {
                case SM2P256V1:
                    signatureWithCheckSum = addCheckSumToSignature(decodedSignature,
                            SM2P256V1_CHECKSUM_VALIDATION_SUFFIX.getBytes());
                    signaturePrefix = PATTERN_STRING_EOS_PREFIX_SIG_SM2;
                    break;
                case SECP256K1:
                    signatureWithCheckSum = addCheckSumToSignature(decodedSignature,
                            SECP256K1_CHECKSUM_VALIDATION_SUFFIX.getBytes());
                    signaturePrefix = PATTERN_STRING_EOS_PREFIX_SIG_K1;
                    break;
                default:
                    throw new Exception("Unsupported algorithm!");

            }

            //Base58 encode signature and add pertinent EOS prefix
            icbsFormattedSignature = signaturePrefix.concat(Base58.encode(signatureWithCheckSum));

        } catch (Exception e) {
            throw new Exception("An error occured formating the signature!", e);
        }

        return icbsFormattedSignature;
    }

    /**
     * Takes the S value of an ECDSA DER encoded signature and converts it to a low value.
     *
     * @param s S value from signature
     * @param keyType Algorithm used to generate private key that signed the message.
     * @return Low S value
     * @throws LowSVerificationError when the S value determination fails.
     */
    private static BigInteger checkAndHandleLowS(BigInteger s, AlgorithmEmployed keyType)
            throws Exception {
        if (!isLowS(s, keyType)) {
            switch (keyType) {
                case SECP256K1:
                    return K1_CURVE.getN().subtract(s);

                default:
                    return SM2_CURVE.getN().subtract(s);
            }
        }

        return s;
    }

    /**
     * Takes the S value of an ECDSA DER encoded signature and determines whether the value is low.
     *
     * @param s S value from signature
     * @param keyType Algorithm used to generate private key that signed the message.
     * @return boolean indicating whether S value is low
     * @throws LowSVerificationError when the S value determination fails.
     */
    private static boolean isLowS(BigInteger s, AlgorithmEmployed keyType)
            throws Exception {
        int compareResult;

        switch (keyType) {
            case SM2P256V1:
                compareResult = s.compareTo(SM2_HALF_CURVE_ORDER);
                break;

            case SECP256K1:
                compareResult = s.compareTo(K1_HALF_CURVE_ORDER);
                break;

            default:
                throw new Exception("Unsupported algorithm!");
        }

        return compareResult == 0 || compareResult == -1;
    }

    /**
     * Digesting input byte[] to RIPEMD160 format
     *
     * @param input - input byte[]
     * @return RIPEMD160 format
     */
    private static byte[] digestRIPEMD160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(output, 0);

        return output;
    }

    /**
     * Adding checksum to signature
     *
     * @param signature - signature to get checksum added
     */
    private static byte[] addCheckSumToSignature(byte[] signature, byte[] keyTypeByteArray) {
        byte[] signatureWithKeyType = Bytes.concat(signature, keyTypeByteArray);
        byte[] signatureRipemd160 = digestRIPEMD160(signatureWithKeyType);
        byte[] checkSum = Arrays.copyOfRange(signatureRipemd160, 0, CHECKSUM_BYTES);
        return Bytes.concat(signature, checkSum);
    }

    /**
     * Check if the input signature is canonical
     *
     * @param signature - signature to check for canonical
     * @return whether the input signature is canonical
     */
    private static boolean isCanonical(byte[] signature) {
        return (signature[1] & ((Integer) 0x80).byteValue()) == ((Integer) 0x00).byteValue()
                && !(signature[1] == ((Integer) 0x00).byteValue()
                        && ((signature[2] & ((Integer) 0x80).byteValue()) == ((Integer) 0x00)
                                .byteValue()))
                && (signature[33] & ((Integer) 0x80).byteValue()) == ((Integer) 0x00).byteValue()
                && !(signature[33] == ((Integer) 0x00).byteValue()
                        && ((signature[34] & ((Integer) 0x80).byteValue()) == ((Integer) 0x00)
                                .byteValue()));
    }

    /**
     * Getting recovery id from R and S
     *
     * @param r - R in DER of Signature
     * @param s - S in DER of Signature
     * @param sha256HashMessage - Sha256Hash of signed message
     * @param publicKey - public key to validate
     * @param keyType - key type
     * @return - Recovery id of the signature. From 0 to 3. Return -1 if find nothing.
     */
    private static int getRecoveryId(BigInteger r, BigInteger s, Sha256Hash sha256HashMessage,
            byte[] publicKey, AlgorithmEmployed keyType) {
        for (int i = 0; i < NUMBER_OF_POSSIBLE_PUBLIC_KEYS; i++) {
            byte[] recoveredPublicKey =
                    recoverPublicKeyFromSignature(i, r, s, sha256HashMessage, true, keyType);

            if (Arrays.equals(publicKey, recoveredPublicKey)) {
                return i;
            }
        }

        return -1;
    }

    /**
     * * Copyright 2011 Google Inc. * Copyright 2014 Andreas Schildbach * Copyright 2014-2016 the
     * libsecp256k1 contributors * * Licensed under the Apache License, Version 2.0 (the "License");
     * * you may not use this file except in compliance with the License. * You may obtain a copy of
     * the License at * *    http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by
     * applicable law or agreed to in writing, software * distributed under the License is
     * distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
     * express or implied. * See the License for the specific language governing permissions and *
     * limitations under the License.
     * <p>
     * The method was modified to match what we need
     *
     * <p>Given the components of a signature and a selector value, recover and return the public
     * key that generated the signature according to the algorithm in SEC1v2 section 4.1.6.</p>
     *
     * <p>The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
     * correct one. Because the key recovery operation yields multiple potential keys, the correct
     * key must either be stored alongside the signature, or you must be willing to try each recId
     * in turn until you find one that outputs the key you are expecting.</p>
     *
     * <p>If this method returns null it means recovery was not possible and recId should be
     * iterated.</p>
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from 0 to
     * 3, and if the output is null OR a key that is not the one you expect, you try again with the
     * next recId.</p>
     *
     * @param recId Which possible key to recover.
     * @param r the R components of the signature, wrapped.
     * @param s the S components of the signature, wrapped.
     * @param message Hash of the data that was signed.
     * @param compressed Whether or not the original pubkey was compressed.
     * @param keyType key type
     * @return An ECKey containing only the public part, or null if recovery wasn't possible.
     */
    private static byte[] recoverPublicKeyFromSignature(int recId, BigInteger r, BigInteger s,
            Sha256Hash message, boolean compressed, AlgorithmEmployed keyType) {
        checkArgument(recId >= 0, "recId must be positive");
        checkArgument(r.signum() >= 0, "r must be positive");
        checkArgument(s.signum() >= 0, "s must be positive");

        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn

        BigInteger n; // Curve order.
        ECPoint g;
        ECCurve.Fp curve;

        switch (keyType) {
            case SECP256K1:
                n = ecParamsK1.getN();
                g = ecParamsK1.getG();
                curve = (ECCurve.Fp) ecParamsK1.getCurve();
                break;

            default:
                n = ecParamsSM2.getN();
                g = ecParamsSM2.getG();
                curve = (ECCurve.Fp) ecParamsSM2.getCurve();
                break;
        }

        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));

        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs “invalid”, then
        //        do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = curve.getQ();
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1, keyType);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = message.toBigInteger();
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
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(g, eInvrInv, R, srInv);
        return q.getEncoded(compressed);
    }

    /**
     * * Copyright 2011 Google Inc. * Copyright 2014 Andreas Schildbach * Copyright 2014-2016 the
     * libsecp256k1 contributors * * Licensed under the Apache License, Version 2.0 (the "License");
     * * you may not use this file except in compliance with the License. * You may obtain a copy of
     * the License at * *    http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by
     * applicable law or agreed to in writing, software * distributed under the License is
     * distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
     * express or implied. * See the License for the specific language governing permissions and *
     * limitations under the License.
     * <p>
     * The method was modified to match what we need
     * <p>
     * Decompress a compressed public key (x co-ord and low-bit of y-coord).
     */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit, AlgorithmEmployed keyType) {
        ECCurve.Fp curve;

        switch (keyType) {
            case SECP256K1:
                curve = (ECCurve.Fp) ecParamsK1.getCurve();
                break;

            default:
                curve = (ECCurve.Fp) ecParamsSM2.getCurve();
                break;
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(curve));
        compEnc[0] = (byte) (yBit ? COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y
                : COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y);
        return curve.decodePoint(compEnc);
    }
}
