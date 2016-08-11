<?php

namespace Drupal\encryption;

use Drupal\Core\Site\Settings;

/**
 * Used to encrypt and decrypt text using the 'AES-256-CTR' encryption method
 * using the openssl library that in comes with php unless omitted during
 * compilation.
 *
 * This trait uses an encryption key that should be added to the `$settings
 * array in settings.php. i.e. `$settings['encryption_key']='foo...bar';`
 *
 * An encryption key is a 32 bit binary value that is base63 encoded. On a Mac
 * or linux system, A random encryption key can be created with
 * `dd bs=1 count=32 if=/dev/urandom | openssl base64`.
 *
 * Site instances that share config should use the same encryption key.
 *
 * @package Drupal\encryption
 */
trait EncryptionTrait {

  /**
   * Encrypt a value using the encryption key from settings.php
   *
   * @param $value
   *   The value tobe encrypted.
   * @return string
   *   A Base64 encoded representation of the encrypted value.
   */
  public function encrypt($value) {
    // Get the encryption key.
    if ($key = $this->getEncryptionKey()) {
      // Generates a random initialization vector.
      $iv = openssl_random_pseudo_bytes(16);
      // Generate a HMAC key using the initialization vector.
      $h_key = hash_hmac('sha256', hash('sha256', substr($key, 16), TRUE), sha1($iv, TRUE), TRUE);
      // Concatenate the initialization vector and the encrypted value.
      $cypher = base64_encode($iv).'|'.openssl_encrypt($value, 'AES-256-CTR', $key, FALSE, $iv);
      // Concatenate the format code, hash and cypher.
      return '01'.hash_hmac('sha256', $cypher, $h_key).$cypher;
    }
  }

  /**
   * Decrypt a value using the encryption key from settings.php.
   *
   * @param $value
   *   A Base64 encoded representation of an encrypted string.
   * @return string
   *   The decrypted value.
   */
  public function decrypt($value) {
    // Get the encryption key.
    if ($key = $this->getEncryptionKey()) {
      // Get the cypher hash.
      $hmac = substr($value, 2, 64);
      // Decode the initialization vector.
      $iv = base64_decode(substr($value, 66, 24));
      // Re generate the HMAC key.
      $h_key = hash_hmac('sha256', hash('sha256', substr($key, 16), TRUE), sha1($iv, TRUE), TRUE);
      if ($hmac === hash_hmac('sha256', substr($value, 66), $h_key)) {
        // Decrypt to supplied value.
        return openssl_decrypt(substr($value, 90), 'AES-256-CTR', $key, FALSE, $iv);
      }
    }
  }

  /**
   * Gets the `$settings['encryption_key']` value from settings.php.
   *
   * @return mixed
   *   The encryption key.
   */
  public function getEncryptionKey() {
    $key = base64_decode(Settings::get('encryption_key'));

    // Make sure the key is the correct size.
    if (strlen($key) === 32) {
      return $key;
    }
  }

}
