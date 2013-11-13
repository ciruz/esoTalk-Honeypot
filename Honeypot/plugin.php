<?php
// Copyright 2013 ciruz
if (!defined("IN_ESOTALK")) exit;

ET::$pluginInfo["Honeypot"] = array(
	"name" => "Honeypot",
	"description" => "Spam prevention with invisible form fields.",
	"version" => "0.2",
	"author" => "ciruz",
	"authorEmail" => "me@ciruz.net",
	"authorURL" => "http://www.ciruz.net",
	"license" => "MIT"
);

class ETPlugin_Honeypot extends ETPlugin {

	public function userController_join($sender){
		/**
		* Honeypot Protection Start
		*/
		//hide first input with css, set second & third input to small (document ready isn't always as fast as users eye)
		$css = '<style type="text/css">.form > li.etphp1{display:none;}.form > li.etphp2,.form > li.etphp3{height:1px;}</style>';
       	$sender->addToHead($css);

       	//hide second & third input with js
       	$js = '<script>$(document).ready(function(){ $(".etphp2,.etphp3").css("display", "none"); });</script>';
       	$sender->addToHead($js);

       	//write a simple hash to session
       	if(!ET::$session->get('securityHash'))
       		ET::$session->store('securityHash', md5(time()));
       	/**
       	* Honeypot Protection End
       	*/

		if (ET::$session->user) $sender->redirect(URL(""));

		if (!C("esoTalk.registration.open")) {
			$sender->renderMessage(T("Registration Closed"), T("message.registrationClosed"));
			return;
		}

		$sender->title = T("Sign Up");
		$sender->addToHead("<meta name='robots' content='noindex, noarchive'/>");

		$form = ETFactory::make("form");
		$form->action = URL("user/join");

		if ($form->isPostBack("cancel")) $sender->redirect(URL(R("return")));

		if ($form->validPostBack("submit")) {

			/* Honeypot Protection Start */
			//hidden field "zipcode" has a value OR hidden security hash got changed
			if($form->getValue('zipcode') != '' || ($form->getValue('phone') != ET::$session->get('securityHash')) || $form->getValue('homepage') != '')
				$sender->redirect(URL("")); //redirect to startpage
			/* Honeypot Protection End */

			if ($form->getValue("password") != $form->getValue("confirm"))
				$form->error("confirm", T("message.passwordsDontMatch"));

			if (!$form->errorCount()) {

				$data = array(
					"username" => $form->getValue("username"),
					"email" => $form->getValue("email"),
					"password" => $form->getValue("password"),
					"account" => ACCOUNT_MEMBER
				);

				if (!C("esoTalk.registration.requireEmailConfirmation")) $data["confirmedEmail"] = true;
				else $data["resetPassword"] = md5(uniqid(rand()));

				$model = ET::memberModel();
				$memberId = $model->create($data);

				if ($model->errorCount()) $form->errors($model->errors());

				else {

					if (C("esoTalk.registration.requireEmailConfirmation")) {
						$this->sendConfirmationEmail($data["email"], $data["username"], $memberId.$data["resetPassword"]);
						$sender->renderMessage(T("Success!"), T("message.confirmEmail"));
					}

					else {
						ET::$session->login($form->getValue("username"), $form->getValue("password"));
						$sender->redirect(URL(""));
					}

					return;

				}

			}

		}

		$sender->data("form", $form);
		$sender->render($this->getResource("join.php"));
	}
	
	protected function sendConfirmationEmail($email, $username, $hash){
		sendEmail($email,
			sprintf(T("email.confirmEmail.subject"), $username),
			sprintf(T("email.header"), $username).sprintf(T("email.confirmEmail.body"), C("esoTalk.forumTitle"), URL("user/confirm/".$hash, true))
		);
	}
}
