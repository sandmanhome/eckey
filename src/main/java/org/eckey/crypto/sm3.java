/*
 * @Description: 
 * @Author: kay
 * @Date: 2020-09-23 12:02:42
 * @LastEditTime: 2020-09-23 16:20:30
 * @LastEditors: sandman
 */
package org.eckey.crypto;

import org.bouncycastle.crypto.digests.SM3Digest;

public class sm3 {
  private SM3Digest digest;

  public sm3() {
    digest = new SM3Digest();
    reset();
  }
  
  public void update(byte[] src) {
    update(src, 0, src.length);
  }

  public void update(byte[] src, int offset, int length) {
    digest.update(src, offset, length);
  }

  public byte[] doFinal() {
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    reset();
    return hash;
  }

  public void reset() {
    digest.reset();
  }

  public byte[] hash(byte[] src) {
    update(src);
    byte[] hash = doFinal();
    reset();
    return hash;
  }
}