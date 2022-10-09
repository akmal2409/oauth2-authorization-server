package com.akmal.oauth2authorizationserver.crypto;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.config.InternalOAuth2ConfigurationProperties;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RsaKeyServiceTest {

//  private static final String KEYS_DIRECTORY_NAME = "test_keys";
//  private static final String PUB_KEY_NAME = "public.key";
//  private static final String PRIV_KEY_NAME = "private.key";
//  private static final Path CONTEXT_DIR_PATH = Paths.get(System.getProperty("java.io.tmpdir"), "test_files");
//
//  RsaKeyService rsaKeyService;
//
//  @BeforeAll
//  void setup() {
//
//  }
//
//  @BeforeEach
//  void beforeEach() throws IOException {
//    Files.deleteIfExists(Paths.get(System.getProperty("java.io.tmpdir"), KEYS_DIRECTORY_NAME));
//  }
//
//  @Test
//  @DisplayName("Test initKeys() creation of a folder hierarchy when the folders do not exist")
//  void testInitKeysCreationOfFoldersWhenFoldersDoNotExist()
//      throws IOException, NoSuchAlgorithmException {
//
//    when(internalOAuth2ConfigurationProperties.getConfigDir()).thenReturn(CONTEXT_DIR_PATH);
//    when(internalOAuth2ConfigurationProperties.getKeysDirectoryName()).thenReturn(KEYS_DIRECTORY_NAME);
//    when(internalOAuth2ConfigurationProperties.getPrivateKeyFileName()).thenReturn(PRIV_KEY_NAME);
//    when(internalOAuth2ConfigurationProperties.getPublicKeyFileName()).thenReturn(PUB_KEY_NAME);
//
//    rsaKeyService.initKeys();
//
//    assertThat(Files.exists(CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME)))
//        .isTrue();
//  }
}
