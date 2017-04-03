<?php
/**
 * @file
 * File for the YubiKey_Login_Exception class declaration.
 */

class YubiKey_Login_Exception extends Exception
{

  public function __construct($message, $previous_exception=NULL)
  {
    parent::__construct($message, 0, $previous_exception);
  }

}
