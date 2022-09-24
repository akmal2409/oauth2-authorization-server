package com.akmal.oauth2authorizationserver.utils;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.akmal.oauth2authorizationserver.shared.utils.ByteUtils;
import org.junit.jupiter.api.Test;

class ByteUtilsTest {

  @Test
  void longToByteArray() {
    long givenNumber = 1152902738463079355L;
    byte[] expected = new byte[]{(byte) 0x0F, (byte) 0xFF, (byte) 0xEE, (byte) 0xEE, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xBB, (byte) 0xBB};

    // when
    byte[] actual = ByteUtils.longToByteArray(givenNumber);

    //then
    assertThat(actual)
        .isNotNull()
        .containsExactly(expected);
  }
}
