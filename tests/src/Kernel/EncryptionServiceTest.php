<?php

namespace Drupal\Tests\encryption\Kernel;


use Drupal\encryption\EncryptionServiceInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Core\Site\Settings;

class EncryptionServiceTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'encryption',
  ];

  public function setUp() {
    parent::setUp();

    // Get the settigns object.
    $settings = Settings::getAll();
    // Add a randomly generated encryption key.
    new Settings($settings + ['encryption_key' => base64_encode(random_bytes(32))]);
  }

  public function testEncryptionService() {
    $super_secret_string = 'Big time secrets!';

    // Get the encryption service.
    $encryption_service = \Drupal::service('encryption');
    // Encrypt top secret stuff.
    $encrypted_value = $encryption_service->encrypt($super_secret_string);
    // Decrypt top secret stuff.
    $decrypted_value = $encryption_service->decrypt($encrypted_value);

    // Make sure the encryption service implements it's interface
    self::assertTrue($encryption_service instanceof EncryptionServiceInterface);

    // Make sure there was at least some change to the value.
    self::assertNotEquals($encrypted_value, $super_secret_string);

    // Make sure the value get's encrypted properly.
    self::assertEquals($super_secret_string, $decrypted_value);
  }
}
