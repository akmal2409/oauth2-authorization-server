package com.akmal.oauth2authorizationserver.crypto;

import com.akmal.oauth2authorizationserver.exception.crypto.KeyNotAvailableException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class RsaKeyService {

  private static final Path KEYS_FOLDER_PATH = Paths.get(".authorization_server", "keys");
  private static final Path PUBLIC_KEY_PATH = KEYS_FOLDER_PATH.resolve("public.key");
  private static final Path PRIVATE_KEY_PATH = KEYS_FOLDER_PATH.resolve("private.key");

  private volatile KeyPair keyPair = null;

  /**
   * The method will be run in the background thread as soon as the application is ready but
   * when the CLI is still unavailable. That gives us enough of time to initialize the keys and load them
   * into the context. Since only owning thread can modify the key, synchronization is achieved through using
   * atomic references for visibility.
   * The method generates RSA 2048-bit long key pair that is stored in the directory ${user.home}/${@link RsaKeyService#KEYS_FOLDER_PATH}.
   * If at least one of the keys is missing, it will generate a new keypair and overwrite the old one.
   *
   * @throws IOException if the key files could not be read/written to.
   * @throws NoSuchAlgorithmException if the RSA algorithm is not available.
   */
  @EventListener(ApplicationStartedEvent.class)
  @Async
  public void initKeys() throws IOException, NoSuchAlgorithmException {
    final var userHomePath = Paths.get(System.getProperty("user.home"));
    final var keyDirectory = userHomePath.resolve(KEYS_FOLDER_PATH);

    if (!Files.exists(keyDirectory)) {
      log.info("Creating directories to store public/private keys.");
      Files.createDirectories(keyDirectory);
    }

    final var publicKeyPath = userHomePath.resolve(PUBLIC_KEY_PATH);
    final var privateKeyPath = userHomePath.resolve(PRIVATE_KEY_PATH);

    try {
      KeyPair keyPair = null;

      if (!Files.exists(publicKeyPath) || !Files.exists(privateKeyPath)) {
        keyPair = this.generateKeyPair();

        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        log.info("Completed creation of public key. Available at: {}", publicKeyPath);
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        log.info("Completed creation of private key. Available at: {}", privateKeyPath);
      } else {
        keyPair = this.loadKeyPair(publicKeyPath, privateKeyPath);
      }

      this.keyPair = keyPair;
      log.info("Loaded private/public key into the context");
    } catch (IOException e) {
      log.error("IO exception occurred during key initialization", e);
    } catch (NoSuchAlgorithmException e) {
      log.error("Invalid algorithm passed to key factory", e);
    } catch (InvalidKeySpecException e) {
      log.error("Invalid key specification", e);
    }
  }

  /**
   * Method loads private and public key pair as provided in paths of the keys.
   * The private key format must be of {@link PKCS8EncodedKeySpec} and the public key format
   * {@link X509EncodedKeySpec}, other types will throw an InvalidKeySpecException.
   *
   * Supports only binary encoded keys.
   *
   * @param publicKeyPath absolute path to the public key.
   * @param privateKeyPath absolute path to the private key.
   * @return {@link KeyPair}
   * @throws IOException if the files could not be read.
   * @throws NoSuchAlgorithmException if algorithm is not available.
   * @throws InvalidKeySpecException if the key specification is wrong.
   */
  private KeyPair loadKeyPair(Path publicKeyPath, Path privateKeyPath)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
    byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    // generate private key
    final KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

    // generate public key
    final KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

    return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
  }

  private KeyPair generateKeyPair()
      throws NoSuchAlgorithmException, IOException {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    keyGenerator.initialize(2048);
    return keyGenerator.generateKeyPair();
  }

  public KeyPair getKeyPair() {
    if (this.keyPair == null) throw new KeyNotAvailableException("Public/private key pair is not available");
    return this.keyPair;
  }
}
