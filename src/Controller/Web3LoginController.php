<?php

namespace Drupal\web3login\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Elliptic\EC;
use kornrunner\keccak;

use Symfony\Component\HttpFoundation\Response;

/**
 * Class Web3LoginController.
 *
 * @package Drupal\web3login\Controller
 */
class Web3LoginController extends ControllerBase {

  private LoggerInterface $logger;

  private string $MessageText = 'Allow login at ';

  /**
   * Constructs a Web3LoginController object.
   */
  public function __construct(LoggerInterface $logger) {
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $entity_type_manager = $container->get('entity_type.manager');

    return new static(
      $container->get('logger.factory')->get('web3login')
    );
  }

  /**
   * Authorize web3login user login.
   */
  public function verifyLogin(Request $request) {
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
        $user = \Drupal::entityTypeManager()->getStorage('user')->load($wallet_uid);
        break;
      } 
    }

    // Make sure we have a user.
    if (!$user) {
      return new Response( $this->t('User not found'), 404);
    }

    if (empty($user_wallet_address)) {
      return new Response($this->t('User has no wallet address set.'), 400);
    }

    $message = $this->MessageText . $nonce;
    $verify_signature_wallet = $this->verifySignature($message, $sig, $user_wallet_address);


    if (!$verify_signature_wallet) {
      return $this->accessDenied();
    }

    // Finalize login
    user_login_finalize($user);

    // Redirect to the user's profile page.
    return new RedirectResponse("/user/{$user->id()}");
  }


  /**
   * Reject web3login user login.
   */
  public function accessDenied(): array {
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
   * @return string[]
   *   A render array.
   */
  private function respondWithError(string $message): array {
    if (!empty($message)) {
      $this->logger->error($message);
    }

    return [
      '#markup' => "<p>{$message}</p>",
    ];
  }


}
