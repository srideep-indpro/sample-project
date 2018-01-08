package com.customsecurity.module;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.activemq.jaas.UserPrincipal;
import org.apache.log4j.Logger;

public class AuthModule extends Thread implements LoginModule {
	private static final Logger LOG = Logger.getLogger(AuthModule.class.getName());
	private CallbackHandler callbackHandler;
	private Subject subject;
	private boolean succeeded;
	private boolean isAdmin;
	private boolean commitSucceeded;
	private String user;
	private Set<Principal> principals;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		this.callbackHandler = callbackHandler;
		this.subject = subject;
	}

	@Override
	public boolean login() throws LoginException {
		LOG.info("logged in successfully");
		if (callbackHandler == null) {
			throw new LoginException("No callback handler supplied.");
		}
		Callback callbacks[] = new Callback[2];
		callbacks[0] = new NameCallback("Username");
		callbacks[1] = new PasswordCallback("Password", false);

		try {
			callbackHandler.handle(callbacks);
			String username = ((NameCallback) callbacks[0]).getName();
			char passwordCharArray[] = ((PasswordCallback) callbacks[1]).getPassword();
			String password = new String(passwordCharArray);
			subject.getPublicCredentials().add(username);
			subject.getPrivateCredentials().add(password);
			user = username;
			logOnConsole("Incoming Credentials::::");
			logOnConsole("USERNAME : " + username);
			logOnConsole("PASSWORD : " + password);
		} catch (IOException | UnsupportedCallbackException e) {
			e.printStackTrace();
		}
		return succeeded;
	}

	@Override
	public boolean commit() throws LoginException {
		if (!succeeded) {
			logout();
			return false;
		}
		principals.add(new UserPrincipal(user));
		if (isAdmin) {
			principals.add(new org.apache.activemq.jaas.GroupPrincipal("ADMINS"));
		} else {
			principals.add(new org.apache.activemq.jaas.GroupPrincipal("USERS"));
		}
		subject.getPrincipals().addAll(principals);
		commitSucceeded = true;
		clear();
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		clear();
		if (!succeeded) {
			return false;
		}
		if (succeeded && !commitSucceeded) {
			succeeded = false;
		} else {
			logout();
		}
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		subject.getPrincipals().removeAll(principals);
		principals.clear();
		succeeded = false;
		commitSucceeded = false;
		return true;
	}

	private void clear() {
		user = null;
	}

	private void logOnConsole(Object message) {
		LOG.info((String) message + System.lineSeparator());
	}

}
