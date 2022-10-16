package com.akmal.oauth2authorizationserver.crypto;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.config.InternalOAuth2ConfigurationProperties;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Random;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
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

  private static final String KEYS_DIRECTORY_NAME = "test_keys";
  private static final Path CONTEXT_DIR_PATH = Paths.get(System.getProperty("java.io.tmpdir"),
      "test_files");
  public static final String KEY_ALG = "RSA";
  public static final int KEY_LENGTH = 2048;
  public static final String KEYSTORE_NAME = "test_keystore.p12";
  public static final String KEYSTORE_TYPE = "PKCS12";
  public static final String SIGNATURE_ALG = "SHA256withRSA";
  public static final String PRIVATE_KEY_ALIAS = "private.key";
  public static final String KEY_STORE_PASSWORD = "123434234324";
  public static final String ISSUER_URL = "http://test.localhost.local:8080";
  public static final int TOKEN_VALIDITY_MS = 1000;


  RsaKeyService rsaKeyService;

  RsaKeyServiceTest() {
    final var props = new InternalOAuth2ConfigurationProperties();
    props.setKeyAlg(KEY_ALG);
    props.setKeyLength(KEY_LENGTH);
    props.setKeyStoreName(KEYSTORE_NAME);
    props.setKeyStoreType(KEYSTORE_TYPE);
    props.setKeysDirectoryName(KEYS_DIRECTORY_NAME);
    props.setConfigDir(CONTEXT_DIR_PATH);
    props.setSignatureAlg(SIGNATURE_ALG);
    props.setPrivateKeyAlias(PRIVATE_KEY_ALIAS);
    props.setKeyStorePassword(KEY_STORE_PASSWORD);
    props.setIssuerUrl(ISSUER_URL);
    props.setTokenValidityMs(TOKEN_VALIDITY_MS);
    this.rsaKeyService = new RsaKeyService(props);
  }


  @BeforeEach
  void beforeEach() throws IOException {
    Files.deleteIfExists(Paths.get(System.getProperty("java.io.tmpdir"), KEYS_DIRECTORY_NAME));
  }

  @AfterAll
  static void cleanup() throws IOException {
    Files.deleteIfExists(Paths.get(System.getProperty("java.io.tmpdir"), KEYS_DIRECTORY_NAME));
  }

  @Test
  @DisplayName("Test initKeys() creation of a folder hierarchy when the folders do not exist")
  void testInitKeysCreationOfFoldersWhenFoldersDoNotExist()
      throws IOException, NoSuchAlgorithmException {
    rsaKeyService.initKeys();

    assertThat(Files.exists(CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME)))
        .isTrue();

    assertThat(Files.isDirectory(CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME)))
        .isTrue();
  }

  @Test
  @DisplayName("Test initKeys() should load existing keystore")
  void testInitKeysShouldLoadExistingKeystore()
      throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {
    // create dummy Keystore
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    final var store = KeyStore.getInstance(KEYSTORE_TYPE);
    store.load(null, null);
    final var keyPair = generateKeyPair(1024, KEY_ALG);
    final var cert = generateCertificate(keyPair.getPrivate(), keyPair.getPublic(),
        SIGNATURE_ALG, "BC", "CN=root", 100);
    store.setKeyEntry("test_mutation", keyPair.getPrivate(), KEY_STORE_PASSWORD.toCharArray(), new Certificate[]{cert});

    final var keyStoreDirectory = CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME).toFile();
    if (!keyStoreDirectory.exists()) keyStoreDirectory.mkdirs();
    final var keystoreFile = CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME).resolve(KEYSTORE_NAME).toString();

    try (final var out = new FileOutputStream(keystoreFile)) {
      store.store(out, KEY_STORE_PASSWORD.toCharArray());
    }

    rsaKeyService.initKeys();

    try (final var in = new FileInputStream(keystoreFile)) {
      store.load(in, KEY_STORE_PASSWORD.toCharArray());
    }

    assertThat(store.containsAlias("test_mutation")).isTrue(); // assert that the file has not been changed.
  }


  @Test
  @DisplayName("Test initKeys() should create a keystore with a keystore type and password specified in the props")
  void testInitKeysShouldCreateKeystoreWithTypeAndPassword()
      throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
    File keystoreFile = CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME).resolve(KEYSTORE_NAME)
                            .toFile();

    rsaKeyService.initKeys();

    KeyStore store = KeyStore.getInstance(KEYSTORE_TYPE);

    assertThat(keystoreFile).exists();
    try (final var in = new FileInputStream(keystoreFile)) {
      store.load(in, KEY_STORE_PASSWORD.toCharArray());
    }
  }

  @Test
  @DisplayName("Test initKeys() should create public/private key pair with specified keys size and type")
  void testInitKeysShouldCreateKeysWithTypeAndSize()
      throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException {
    File keystoreFile = CONTEXT_DIR_PATH.resolve(KEYS_DIRECTORY_NAME).resolve(KEYSTORE_NAME)
                            .toFile();
    rsaKeyService.initKeys();

    KeyStore store = KeyStore.getInstance(KEYSTORE_TYPE);

    try (final var in = new FileInputStream(keystoreFile)) {
      store.load(in, KEY_STORE_PASSWORD.toCharArray());
    }

    final var privateKeyEntry = (PrivateKeyEntry) store.getEntry(PRIVATE_KEY_ALIAS,
        new PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));

    assertThat(privateKeyEntry).isNotNull()
        .extracting(PrivateKeyEntry::getPrivateKey).isNotNull()
        .extracting(PrivateKey::getAlgorithm).isEqualTo(KEY_ALG);

    assertThat(privateKeyEntry).extracting(PrivateKeyEntry::getCertificate)
        .isNotNull()
        .extracting(Certificate::getPublicKey)
        .isNotNull()
        .extracting(PublicKey::getAlgorithm).isEqualTo(KEY_ALG);

    final var rsaPrivKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
    final var rsaPubKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

    assertThat(rsaPrivKey)
        .extracting(RSAPrivateKey::getModulus)
        .asInstanceOf(InstanceOfAssertFactories.BIG_INTEGER)
        .extracting(BigInteger::bitLength).isEqualTo(KEY_LENGTH);

    assertThat(rsaPubKey)
        .extracting(RSAPublicKey::getModulus)
        .asInstanceOf(InstanceOfAssertFactories.BIG_INTEGER)
        .extracting(BigInteger::bitLength).isEqualTo(KEY_LENGTH);
  }

  @Test
  @DisplayName("Test initKeys() bouncy castle is added as a security provider under the name BC for certificate generation")
  void testInitKeysShouldAddBCAsSecurityProvider() throws IOException, NoSuchAlgorithmException {
    rsaKeyService.initKeys();

    final var actualProvider = Security.getProvider("BC");
    assertThat(actualProvider).isNotNull()
        .extracting(Provider::isConfigured)
        .isEqualTo(true);
  }

  private X509Certificate generateCertificate(PrivateKey privateKey, PublicKey publicKey, String signatureAlgorithm, String provider, String canonicalName, long validitySeconds)
      throws OperatorCreationException, CertificateException {
    final var startDate = new Date();
    final var endDate =  new Date();
    endDate.setTime(startDate.getTime() + validitySeconds * 1000);

    X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
        new X500Name(canonicalName),
        BigInteger.valueOf(new Random().nextLong()),
        new Date(Instant.now().toEpochMilli()),
        new Date(Instant.now().plus(Duration.ofSeconds(validitySeconds)).toEpochMilli()),
        new X500Name("CN=root2"),
        publicKey);

    ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                               .setProvider(provider)
                               .build(privateKey);

    return new JcaX509CertificateConverter()
               .setProvider(provider)
               .getCertificate(certificate.build(signer));
  }

  private KeyPair generateKeyPair(int keySize, String keyAlgorithm)
      throws NoSuchAlgorithmException {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(keyAlgorithm);

    keyGenerator.initialize(keySize, new SecureRandom());
    return keyGenerator.generateKeyPair();
  }
}
