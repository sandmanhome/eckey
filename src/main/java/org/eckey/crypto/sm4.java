/*
 * @Description: 
 * @Author: kay
 * @Date: 2020-09-23 08:32:16
 * @LastEditTime: 2020-09-23 14:06:33
 * @LastEditors: kay
 */
package org.eckey.crypto;

import java.security.Key;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

public class sm4 {
  public static final String ALGORITHM_NAME = "SM4";
  public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
  public static final String ALGORITHM_NAME_ECB_NO_PADDING = "SM4/ECB/NoPadding";
  public static final int DEFAULT_KEY_SIZE = 128;

  private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
    Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
    cipher.init(mode, sm4Key);
    return cipher;
  }

  public static String encrypt(byte[] msgBytes, String hexKey) throws Exception {
    return encrypt(msgBytes, hexKey, true);
  }

  public static String encrypt(byte[] msgBytes, String hexKey, Boolean padding) throws Exception {
    byte[] keyData = ByteUtils.fromHexString(hexKey);
    byte[] cipherArray = encrypt_Ecb_Padding(msgBytes, keyData, padding);
    String cipherText = ByteUtils.toHexString(cipherArray);
    return cipherText;
  }

  public static byte[] decrypt(String encryptData, String hexKey) throws Exception {
    return decrypt(encryptData, hexKey, true);
  }

  public static byte[] decrypt(String encryptData, String hexKey, Boolean padding) throws Exception {
    byte[] keyData = ByteUtils.fromHexString(hexKey);
    byte[] cipherData = ByteUtils.fromHexString(encryptData);
    String algorithmName = ALGORITHM_NAME_ECB_PADDING;
    if (!padding) {
      algorithmName = ALGORITHM_NAME_ECB_NO_PADDING;
    }
    Cipher cipher = generateEcbCipher(algorithmName, Cipher.DECRYPT_MODE, keyData);
    return cipher.doFinal(cipherData);
  }

  private static byte[] encrypt_Ecb_Padding(byte[] data, byte[] key, Boolean padding) throws Exception {
    String algorithmName = ALGORITHM_NAME_ECB_PADDING;
    if (!padding) {
      if (data.length % 16 != 0) {
        byte[] nopadded = new byte[data.length - (data.length % 16)];
        System.arraycopy(data, 0, nopadded, 0, nopadded.length);
        data = nopadded;
      }
      algorithmName = ALGORITHM_NAME_ECB_NO_PADDING;
    }
    Cipher cipher = generateEcbCipher(algorithmName, Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }
}