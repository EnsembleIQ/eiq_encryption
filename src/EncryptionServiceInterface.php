<?php

namespace Drupal\encryption;

/**
 * Interface EncryptionServiceInterface.
 *
 * @package Drupal\encryption
 */
interface EncryptionServiceInterface {

  /**
   * Encrypt a value using the encryption key from settings.php
   *
   * @param $value
   *   The value tobe encrypted.
   * @return string
   *   A Base64 encoded representation of the encrypted value.
   */
  public function encrypt($value);

  /**
   * Decrypt a value using the encryption key from settings.php.
   *
   * @param $value
   *   A Base64 encoded representation of an encrypted string.
   * @return string
   *   The decrypted value.
   */
  public function decrypt($value);

  /**
   * Gets the `$settings['encryption_key']` value from settings.php.
   *
   * @return mixed
   *   The encryption key.
   */
  public function getEncryptionKey();

}
