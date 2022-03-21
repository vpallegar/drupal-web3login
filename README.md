# Web3 Login

This module allows for users to login via their web3 wallet.

Administrators can provide the ability to enable web3 login and set public addresses for any drupal user account.

Features:
Web3 wallet login
Require message signature for verification
Ethereum network support

Administrator settings page:
`/admin/config/web3login`

## Installation

1.  Install `composer require simplito/elliptic-php` & `composer require kornrunner/keccak` (used for verifying signatures).
2.  Install this web3login module and enable it `drush en web3login`.
3.  Visit  `/admin/config/web3login` page and enable web3 login.
4.  Edit an individual user's settings and add their web3 wallet address (This is their ethereum wallet address).
5.  After enabled, a web3 login button will appear on the login form. Clicking this button will redirect the user to the web3 wallet provider (ie metamask).  The user will need to sign a message upon logging in, which will prove that they own this wallet (this transaction does not cost any gas).  The user will then be able to login to the site.


### Disclaimer

Please note this is under active development so please use at your own risk.  More security features will be added in the future.