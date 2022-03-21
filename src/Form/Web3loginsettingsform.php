<?php

/**
 * @file
 * Contains \Drupal\web3login\Form\Web3LoginSettingsForm.
 * Web3login settings form.
 */

namespace Drupal\web3login\Form;

use Drupal\Core\Form\ConfigFormBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\file\Entity\File;

/**
 * Defines a form that configure settings.
 */
class Web3LoginSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    parent::__construct($config_factory);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'web3login_admin_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'web3login.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, Request $request = NULL) {

    $form_state->disableCache();

    $web3login_config = $this->config('web3login.settings');
    
    $form['network_options'] = array(
      '#type' => 'value',
      '#value' => array('1' => t('Ethereum'))
    );

    $form['web3login'] = array(
      '#type'            => 'details',
      '#title'           => $this->t('Configuration'),
      '#open'            => TRUE,
       
      'active' => array(
        '#type'          => 'checkbox',
        '#title'         => $this->t('Enable Web3 Login'),
        '#default_value' => $web3login_config->get('active'),
        '#description'   => $this->t('If enabled, you can edit a user account and enable web3 login with their address'),
      ),
      'network' => array(
        '#title' => t('Network'),
        '#type' => 'select',
        '#description' => $this->t("Select which network to use for web3 login wallet."),
        '#options' => $form['network_options']['#value'],
      )
    );
    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();

    $this->config('web3login.settings')    
      ->set('active', $values['active'])
      ->set('network', $values['network'])
      ->save();

    drupal_flush_all_caches();
  }
}