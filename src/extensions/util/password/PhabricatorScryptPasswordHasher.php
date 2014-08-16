<?php

/**
 * Library for scrypt password hashing support.
 *
 * @task internal Internals
 */
final class PhabricatorScryptPasswordHasher
  extends PhabricatorPasswordHasher {

/* -(  Implementation  )----------------------------------------------------- */

  public function getHumanReadableName() {
    return pht('scrypt');
  }

  public function getHashName() {
    return 'scrypt';
  }

  public function getHashLength() {
    // logN | r | p | salt | bin2hex(password)
    return 109;
  }

  public function canHashPasswords() {
    return function_exists('scrypt');
  }

  public function getInstallInstructions() {
    return pht('Install the `scrypt` extension via PECL.');
  }

  public function getStrength() {
    return 4.0;
  }

  public function getHumanReadableStrength() {
    return pht('Great');
  }

  protected function getPasswordHash(PhutilOpaqueEnvelope $envelope) {
    list($logN, $r, $p) = $this->getScryptParams();
    $salt = Filesystem::readRandomCharacters(16);

    return new PhutilOpaqueEnvelope(
      $this->createHash($envelope->openEnvelope(), $salt, $logN, $r, $p));
  }

  protected function verifyPassword(
    PhutilOpaqueEnvelope $password,
    PhutilOpaqueEnvelope $hash) {
    return $this->verifyPass($password->openEnvelope(), $hash->openEnvelope());
  }

  protected function canUpgradeInternalHash(PhutilOpaqueEnvelope $hash) {
    $info = $this->getParams($hash->openEnvelope());

    // NOTE: If the costs don't match -- even if the new cost is lower than
    // the old cost -- count this as an upgrade. This allows costs to be
    // adjusted down and hashing to be migrated toward the new cost if costs
    // are ever configured too high for some reason.

    if ($info !== $this->getScryptParams()) {
      return true;
    }

    return false;
  }

/* -(  Internals  )---------------------------------------------------------- */

  private function getScryptParams() {
    // Recommended interactive scrypt parameters.
    return array(14, 8, 1);
  }

  private function verifyPass($pass, $hash) {
    list($logN, $r, $p, $salt, $raw_hash) = $this->separateHash($hash);

    $pass_hash = $this->createHash($pass, $salt, $logN, $r, $p);
    return $pass_hash === $hash; /* TODO FIXME */
  }

  /**
   * Create a fully 'serialized' hash with included parameters.
   */
  private function createHash($raw_input, $salt, $logN, $r, $p) {
    $hash = scrypt(
      $raw_input, $salt,
      pow(2, intval($logN)), intval($r), intval($p),
      40);

    // Format numbers to three decimal places for accurate hash lengths,
    // since the 40 byte output and 16 byte salt are statically known.
    $logN = sprintf('%03d', $logN);
    $r    = sprintf('%03d', $r);
    $p    = sprintf('%03d', $p);
    return implode('|', array($logN, $r, $p, $salt, $hash));
  }

  /**
   * Get the parameters used for a hashed password.
   */
  private function getParams($hash) {
    list($logN, $r, $p, $salt, $raw_hash) = $this->separateHash($hash);
    return array($logN, $r, $p);
  }

  /**
   * Split a hashed password into its internal components.
   */
  private function separateHash($hash) {
    list($logN, $r, $p, $salt, $raw_hash) = explode('|', $hash);
    return array(intval($logN), intval($r), intval($p), $salt, $raw_hash);
  }

}

// Local Variables:
// fill-column: 80
// indent-tabs-mode: nil
// c-basic-offset: 2
// buffer-file-coding-system: utf-8-unix
// End:
