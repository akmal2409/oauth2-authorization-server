package com.akmal.oauth2authorizationserver.crypto;

import com.akmal.oauth2authorizationserver.config.InternalOAuth2ConfigurationProperties;
import com.akmal.oauth2authorizationserver.exception.crypto.KeyNotAvailableException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class RsaKeyService {

  private final Path keysFolderPath;
  private final Path keyStorePath;
  private volatile KeyPair keyPair = null;

  private final InternalOAuth2ConfigurationProperties internalOauth2ConfigProps;

  public RsaKeyService(InternalOAuth2ConfigurationProperties internalOauth2ConfigProps) {
    this.internalOauth2ConfigProps = internalOauth2ConfigProps;
    this.keysFolderPath = internalOauth2ConfigProps.getConfigDir().resolve(internalOauth2ConfigProps.getKeysDirectoryName());
    this.keyStorePath = keysFolderPath.resolve(internalOauth2ConfigProps.getKeyStoreName());
  }

  /**
   * The method will be run in the background thread as soon as the application is ready but
   * when the CLI is still unavailable. That gives us enough of time to initialize the keys and load them
   * into the context. Since only owning thread can modify the key, synchronization is achieved through using
   * atomic references for visibility.
   * The method generates RSA 2048-bit long key pair that is stored in the directory ${user.home}/${@link RsaKeyService#}.
   * If at least one of the keys is missing, it will generate a new keypair and overwrite the old one.
   *
   * @throws IOException if the key files could not be read/written to.
   * @throws NoSuchAlgorithmException if the RSA algorithm is not available.
   */
  @EventListener(ContextRefreshedEvent.class)
  @Async
  public void initKeys() throws IOException, NoSuchAlgorithmException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    if (!Files.exists(keysFolderPath)) {
      log.info("Creating directories to store public/private keys.");
      Files.createDirectories(keysFolderPath);
    }


    try {
      if (!Files.exists(keyStorePath)) {
        log.info("Keystore with does not exist at path: '{}'. Preparing to create", keyStorePath);
        this.createKeyStore(keyStorePath, internalOauth2ConfigProps.getKeyStoreType(), internalOauth2ConfigProps.getKeyStorePassword());
      }

      // at this point keystore is created and we can load it.
      final var keyStore = KeyStore.getInstance(internalOauth2ConfigProps.getKeyStoreType());

      try (final var in = new FileInputStream(keyStorePath.toString())) {
        keyStore.load(in, internalOauth2ConfigProps.getKeyStorePassword().toCharArray());
      }

      KeyPair keyPairLocal = null;

      if (!keyStore.containsAlias(internalOauth2ConfigProps.getCertificateAlias()) || !keyStore.containsAlias(internalOauth2ConfigProps.getPrivateKeyAlias())) {
        keyPairLocal = this.generateKeyPair(internalOauth2ConfigProps.getKeyLength(), internalOauth2ConfigProps.getKeyAlg());

        final X509Certificate certificate = this.generateCertificate(keyPairLocal.getPrivate(), keyPairLocal.getPublic(), internalOauth2ConfigProps.getSignatureAlg(),
            "BC", "CN=root", 346_896_000);

        log.info("Generated X509Certificate with validity {} seconds", 346_896_000);

        // stores both private key and public key, public key is stored in the certificate and can later be obtained through PrivateKeyEntry class.
        keyStore.setKeyEntry(internalOauth2ConfigProps.getPrivateKeyAlias(), keyPairLocal.getPrivate(), internalOauth2ConfigProps.getKeyStorePassword().toCharArray(), new X509Certificate[]{certificate});

        log.info("Completed creation of private/public key pair. Loaded into a key store with name {}", internalOauth2ConfigProps.getKeyStoreName());

        // save the changes made to the keystore
        try (final var out = new FileOutputStream(keyStorePath.toString())) {
          keyStore.store(out, internalOauth2ConfigProps.getKeyStorePassword().toCharArray());
        }

      } else {
        keyPairLocal = this.loadKeyPair(keyStore, internalOauth2ConfigProps.getPrivateKeyAlias(), internalOauth2ConfigProps.getKeyStorePassword());
      }

      this.keyPair = keyPairLocal;
      log.info("Loaded private/public key into the context");
    } catch (IOException e) {
      log.error("IO exception occurred during key initialization", e);
    } catch (NoSuchAlgorithmException e) {
      log.error("Invalid algorithm passed to key factory", e);
    } catch (UnrecoverableKeyException e) {
      log.error("Exception occurred while loading key pair from key store", e);
    } catch (KeyStoreException | CertificateException e) {
      log.error("Exception occurred while reading/creating key store", e);
    } catch (OperatorCreationException | UnrecoverableEntryException e) {
      log.error("Exception occurred while creating certificate", e);
    }
  }

  /**
   * Generates a self signed certificate with Bouncy Castle (BC) as provider. The certificate is intended to be holder of the public key
   * in the key store, it shall not be used for any other purposes.
   *
   * @param privateKey private key instance.
   * @param publicKey public key instance.
   * @param signatureAlgorithm signature algorithm to sign the certificate.
   * @param provider certificate provider (needs to be registered with SecurityManager).
   * @param canonicalName canonical name of the CA.
   * @param validitySeconds validity in seconds (Expiration time is current time in UTC + validity in seconds).
   * @return self signed certificate.
   * @throws OperatorCreationException if the certificate creation failed.
   * @throws CertificateException if the certificate cannot be loaded.
   */
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

  /**
   * Creates a new keystore with of the given type and with a password. Thereafter, it flushes the empty keyStore to the disk
   * as supplied in the keyStorePath param.
   *
   * @param keyStorePath absolute path to the key store file.
   * @param keyStoreType type of the keystore (PKCS12 is recommended).
   * @param keyStorePassword password of the keystore.
   * @throws KeyStoreException if the keystore type is not supported.
   * @throws CertificateException will not be thrown because the keystore is empty.
   * @throws IOException if the keystore file cannot be written to.
   * @throws NoSuchAlgorithmException if the algorithm is not supported.
   */
  private void createKeyStore(Path keyStorePath, String keyStoreType, String keyStorePassword)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    final var keyStore = KeyStore.getInstance(keyStoreType);
    keyStore.load(null, keyStorePassword.toCharArray());

    try (final var out = new FileOutputStream(keyStorePath.toString())) {
      keyStore.store(out, keyStorePassword.toCharArray());
    }
  }

  /**
   * Method loads private and public key pair from the provided key store.
   * The private key format must be of {@link PKCS8EncodedKeySpec} and the public key format
   * {@link X509EncodedKeySpec}, other types will throw an InvalidKeySpecException.
   *
   * @return {@link KeyPair}
   * @throws NoSuchAlgorithmException if algorithm is not available.
   */
  private KeyPair loadKeyPair(KeyStore keyStore, String privateKeyAlias, String keyStorePassword)
      throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(privateKeyAlias, new KeyStore.PasswordProtection(keyStorePassword.toCharArray()));

    return new KeyPair(privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());
  }

  /**
   * Generates public/private key pair according to the specified key algorithm.
   * @param keySize size of the key in bytes.
   * @param keyAlgorithm algorithm for key generation (e.g. RSA private/public key).
   * @return key pair.
   * @throws NoSuchAlgorithmException if the supplied algorithm is not present.
   */
  private KeyPair generateKeyPair(int keySize, String keyAlgorithm)
      throws NoSuchAlgorithmException {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(keyAlgorithm);

    keyGenerator.initialize(keySize, new SecureRandom());
    return keyGenerator.generateKeyPair();
  }

  /**
   * Returns public/private key pair.
   * @throws KeyNotAvailableException if the key has not been initialized.
   */
  public KeyPair getKeyPair() {
    if (this.keyPair == null) throw new KeyNotAvailableException("Public/private key pair is not available");
    return this.keyPair;
  }
}
