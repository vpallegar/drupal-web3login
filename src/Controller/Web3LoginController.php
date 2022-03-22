<?php

namespace Drupal\web3login\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Elliptic\EC;
use kornrunner\keccak;
use Drupal\Core\Database\Connection;

use Symfony\Component\HttpFoundation\Response;

/**
 * Class Web3LoginController.
 *
 * @package Drupal\web3login\Controller
 */
class Web3LoginController extends ControllerBase {

  /**
   * The logger service.
   *
   * @var \Psr\Log\LoggerInterface
   */
  private LoggerInterface $logger;

  /**
   * Active database connection.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected $database;

  /**
   * Default signature text.
   *
   */
  private string $MessageText = 'Allow login at ';

  /**
   * Current user.
   */
  protected $currentUser;

  /**
   * Constructs a Web3LoginController object.
   */
  public function __construct(LoggerInterface $logger, Connection $database) {
    $this->logger = $logger;
    $this->database = $database;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $entity_type_manager = $container->get('entity_type.manager');

    return new static(
      $container->get('logger.factory')->get('web3login'),
      $container->get('database')
    );
  }

  /**
   * Authorize web3login user login.
   */
  public function verifyLogin(Request $request): Response {
    $sig = $request->get('sig') ?? NULL;
    $address = $request->get('address') ?? NULL;
    $nonce = $request->get('nonce') ?? NULL;

    // Make sure we have a signature and a user id.
    if (empty($sig) || empty($address) || empty($nonce)) {
      return new Response($this->t('Missing parameters'), 400);
    }

    // Lets get all userData with addresses and find match to this address.
    $wallet_addresses = \Drupal::service('user.data')->get('web3login', null, 'address');
    foreach($wallet_addresses as $wallet_uid=>$wallet_address) {
      if (strtolower($address) === strtolower($wallet_address)) {
        $user_wallet_address = $wallet_address;
        $this->currentUser = \Drupal::entityTypeManager()->getStorage('user')->load($wallet_uid);
        break;
      } 
    }

    // Make sure we have a user.
    if (!$this->currentUser) {
      return $this->respondWithError('User not found');
    }

    if (!$this->checkNonceIsValid($this->currentUser, $nonce)) {
      $this->log($this->currentUser, 0, $nonce);
      return $this->respondWithError('Access denied');
    }

    if (empty($user_wallet_address)) {
      return $this->respondWithError('User has no wallet address set.');
    }

    $message = $this->MessageText . $nonce;
    $verify_signature_wallet = $this->verifySignature($message, $sig, $user_wallet_address);


    if (!$verify_signature_wallet) {
      $this->log($this->currentUser, 0, $nonce);
      return $this->accessDenied();
    }

    // Finalize login
    user_login_finalize($this->currentUser);
    $this->log($this->currentUser, 1, $nonce);

    // Redirect to the user's profile page.
    return new RedirectResponse("/user/{$this->currentUser->id()}");
  }


  /**
   * Reject web3login user login.
   */
  public function accessDenied(): Response {
    return $this->respondWithError('Access denied');
  }

  /**
   * 
   */
  private function pubKeyToAddress($pubkey) {
    return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
  }

  /**
   * 
   */
  private function verifySignature($message, $signature, $address) {
    $msglen = strlen($message);
    $hash   = Keccak::hash("\x19Ethereum Signed Message:\n{$msglen}{$message}", 256);
    $sign   = ["r" => substr($signature, 2, 64), 
               "s" => substr($signature, 66, 64)];
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27; 
    if ($recid != ($recid & 1)) 
        return false;

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);

    return strtolower($address) == strtolower($this->pubKeyToAddress($pubkey));
  }


  /**
   * 
   */
  private function verifySignature_pass2($message, $signature, $address) {
    /* Pass 2 sign */
    $hash = Keccak::hash($message, 256);
    $sign = ['r' => substr($signature, 2, 64),
      's' => substr($signature, 66, 64), ];
    $recid = ord(hex2bin(substr($signature, 130, 2))) - 27;
      if ($recid != ($recid & 1))
    {
      return false;
    }
    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);
    return strtolower($address) == $this->pubKeyToAddress($pubkey);
  }


  /**
   * Logs and returns an error message.
   *
   * @param string $message
   *   The error message to log.
   *
   */
  private function respondWithError(string $message) {
    if (!empty($message)) {
      $this->logger->error($message);
    }
    
    \Drupal::messenger()->addError($this->t($message));
    return $this->redirect('user.login');
  }

  /**
   * Check if nonce provided for user is still valid.
   */
  private function checkNonceIsValid(AccountInterface $user, int $nonce) {
    $nonce_log = $this->database->select('web3login_log', 'wl')
      ->fields('wl', ['nonce'])
      ->condition('uid', $user->id())
      ->condition('status', 1)
      ->condition('nonce', date("Y-m-d H:i:s", $nonce / 1000), '>=')
      ->execute()
      ->fetchField();

    // If record exist then this nonce was used or a newer one was created
    if ($nonce_log) {
      return FALSE;
    }

    return TRUE;
  }

  /**
   * Logs an error message.
   * 
   * @param AccountInterface $user
   * @param int $status
   * @param int $nonce
   */
  private function log(AccountInterface $user, int $status, int $nonce) : void {
    
        // Lets add weblogin_log.
        $logging = $this->database->insert('web3login_log');
        $logging->fields([
          'uid',
          'status',
          'ipaddr',
          'nonce',
          'created',
        ]);
        $logging->values([
          $user->id(),
          $status,
          $_SERVER['REMOTE_ADDR'],
          date("Y-m-d H:i:s", $nonce / 1000),
          date("Y-m-d H:i:s"),
        ]);
        $logging->execute();
  }


}
