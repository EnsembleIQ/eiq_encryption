<?php

namespace Drupal\encryption;

use Drupal\Core\Site\Settings;

/**
 * Used to encrypt and decrypt text using the 'AES-256-CFB' encryption method
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
    $key = $this->getEncryptionKey();

    // Uses a hash of the encryption key for the initialization vector.
    return openssl_encrypt($value, 'AES-256-CFB', $key, FALSE, substr(md5($key), 0, 16));
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
    $key = $this->getEncryptionKey();
    return openssl_decrypt($value, 'AES-256-CFB', $key, 0, substr(md5($key), 0, 16));
  }

  /**
   * Gets the `$settings['encryption_key']` value from settings.php.
   *
   * @return mixed
   *   The encryption key.
   */
  public function getEncryptionKey() {
    return base64_decode(Settings::get('encryption_key'));
  }

}
