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
    return $this->hasFastScrypt();
  }

  public function getInstallInstructions() {
    return pht(
      'Install the `scrypt` extension via PECL, or enable '.
      'the `auth.allow-weak-scrypt` configuration variable.');
  }

  public function getStrength() {
    if ($this->hasFastScrypt()) {
      return 4.0;
    }
    else {
      return 0.8;
    }
  }

  public function getHumanReadableStrength() {
    if ($this->hasFastScrypt()) {
      return pht('Great');
    }
    else {
      return pht('Bad');
    }
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
    if ($this->hasFastScrypt()) {
      // Recommended interactive scrypt parameters.
      return array(14, 8, 1);
    }
    else {
      // TODO FIXME: TERRIBLE parameters; these are equivalent to litecoin's
      // scrypt, which uses 512kb of RAM. The default parameters are scrypt(14,
      // 8, 1) = 16MB of RAM, but the pure PHP implementation is far too slow
      // for this.
      return array(10, 4, 1);
    }
  }

  private function runScrypt($pass, $salt, $n, $r, $p, $length) {
    $libroot = dirname(phutil_get_library_root('libphutil-scrypt'));
    require_once $libroot.'/externals/zend-scrypt/Hmac.php';
    require_once $libroot.'/externals/zend-scrypt/Key/Derivation/Pbkdf2.php';
    require_once $libroot.'/externals/zend-scrypt/Key/Derivation/Scrypt.php';

    return bin2hex(
      Zend\Crypt\Key\Derivation\Scrypt::calc(
        $pass, $salt, intval($n), intval($r), intval($p), $length));
  }

  private function verifyPass($pass, $hash) {
    list($logN, $r, $p, $salt, $raw_hash) = $this->separateHash($hash);

    $pass_hash = $this->createHash($pass, $salt, $logN, $r, $p);
    return $pass_hash === $hash; /* TODO FIXME */
  }

  private function createHash($raw_input, $salt, $logN, $r, $p) {
    $hash = $this->runScrypt($raw_input, $salt, pow(2, $logN), $r, $p, 40);
    return $this->combineHash($logN, $r, $p, $salt, $hash);
  }

  private function getParams($hash) {
    list($logN, $r, $p, $salt, $raw_hash) = $this->separateHash($hash);
    return array($logN, $r, $p);
  }

  private function combineHash($logN, $r, $p, $salt, $raw_hash) {
    // Format numbers to three decimal places for accurate hash lengths,
    // since the 48 byte output and 16 byte salt are statically known.
    $logN = sprintf("%03d", $logN);
    $r    = sprintf("%03d", $r);
    $p    = sprintf("%03d", $p);
    return implode('|', array($logN, $r, $p, $salt, $raw_hash));
  }

  private function separateHash($hash) {
    list($logN, $r, $p, $salt, $raw_hash) = explode('|', $hash);
    return array(intval($logN), intval($r), intval($p), $salt, $raw_hash);
  }

  private function hasFastScrypt() {
    return extension_loaded('Scrypt') === true;
  }
}

// Local Variables:
// fill-column: 80
// indent-tabs-mode: nil
// c-basic-offset: 2
// buffer-file-coding-system: utf-8-unix
// End:
