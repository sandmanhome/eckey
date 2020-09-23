package org.eckey.crypto;

import org.eckey.crypto.SM2Engine.*;
import org.eckey.core.*;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.security.SecureRandom;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class sm2 {
  public static String doEncrypt(byte[] msgBytes, String publicKey) throws InvalidCipherTextException {
      ECKey key = ECKey.ECKeyFromPublic(publicKey);
      byte[] encodedByte = encrypt(Mode.C1C3C2, key.GetECPublicKeyParameters(), msgBytes);
      return ByteUtils.toHexString(encodedByte);
  }

  public static byte[] doDecrypt(String encrypted, String privateKey) throws InvalidCipherTextException {
      byte[] encryptedBytes = ByteUtils.fromHexString(encrypted);
      ECKey key = ECKey.ECKeyFromPrivate(privateKey);
      return decrypt(Mode.C1C3C2, key.GetECPrivateKeyParameters(), encryptedBytes);
  }

  public static String doSignature(byte[] msgBytes, String privateKey) throws Exception {
    ECKey key = ECKey.ECKeyFromPrivate(privateKey);
    byte[] signedByte = key.doSignWithSM3(msgBytes);
    return ByteUtils.toHexString(signedByte);
  }
  
  public static Boolean doVerifySignature(byte[] msgBytes, String sigHex, String publicKey) throws Exception {
    byte[] sigBytes = ByteUtils.fromHexString(sigHex);
    ECKey key = ECKey.ECKeyFromPublic(publicKey);
    return key.verifySignWithSM3(msgBytes, sigBytes);
  }
  /**
   * @param pubKeyParameters 公钥
   * @param srcData          原文
   * @return 默认输出C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
   * @throws InvalidCipherTextException
   */
  public static byte[] encrypt(ECPublicKeyParameters pubKeyParameters, byte[] srcData)
          throws InvalidCipherTextException {
      return encrypt(Mode.C1C3C2, pubKeyParameters, srcData);
  }

  /**
   * @param mode             指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
   * @param pubKeyParameters 公钥
   * @param srcData          原文
   * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
   * @throws InvalidCipherTextException
   */
  public static byte[] encrypt(Mode mode, ECPublicKeyParameters pubKeyParameters, byte[] srcData)
          throws InvalidCipherTextException {
      SM2Engine engine = new SM2Engine(mode);
      ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
      engine.init(true, pwr);
      return engine.processBlock(srcData, 0, srcData.length);
  }

  public static byte[] decrypt(Mode mode, ECPrivateKeyParameters priKeyParameters, byte[] sm2Cipher)
      throws InvalidCipherTextException {
    SM2Engine engine = new SM2Engine(mode);
    engine.init(false, priKeyParameters);
    return engine.processBlock(sm2Cipher, 0, sm2Cipher.length);
  }
}