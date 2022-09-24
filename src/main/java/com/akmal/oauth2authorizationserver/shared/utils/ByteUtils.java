package com.akmal.oauth2authorizationserver.shared.utils;

public class ByteUtils {

  public static byte[] longToByteArray(long num) {
    byte[] byteArray = new byte[8];

    for (int i = Long.BYTES - 1; i >= 0; i--) {
      byteArray[i] = (byte) (num & 0xFF);
      num >>= Byte.SIZE;
    }
    return byteArray;
  }
}
