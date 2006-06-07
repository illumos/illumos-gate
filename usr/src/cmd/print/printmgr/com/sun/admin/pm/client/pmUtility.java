/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmUtility.java
 * Resource loading and utility classes
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.applet.*;
import java.io.*;
import java.util.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Utility class to provide common functions to the printing
 * manager classes
 */

public class pmUtility {

/*
 * Gets the localized string from the named bundle
 */

    public static String getCopyrightResource(String key) {
	String keyvalue = null;
	ResourceBundle bundle = null;


	try {
		bundle = ResourceBundle.getBundle(
			"com.sun.admin.pm.client.pmCopyright");
	} catch (MissingResourceException e) {
		Debug.fatal("Could not load pmCopyright file");
	}

	try {
		keyvalue = bundle.getString(key);
	} catch (MissingResourceException e) {
		Debug.error("CLNT: getCopyrightResource: Missing: " + key);
           keyvalue = new String("<<" + key + ">>");
	}

	return keyvalue;
    }

    public static String getResource(String key) {
	String keyvalue = null;
	ResourceBundle bundle = null;


	try {
		bundle = ResourceBundle.getBundle(
			"com.sun.admin.pm.client.pmResources");
	} catch (MissingResourceException e) {
		Debug.fatal("Could not load pmResources file");
	}

	try {
		keyvalue = bundle.getString(key);
	} catch (MissingResourceException e) {
		Debug.error("CLNT: getResource: Missing: " + key);
           keyvalue = new String("<<" + key + ">>");
	}

	return keyvalue;
    }

    public static int getIntResource(String key) {
	int keyvalue = 0;
	String s = null;
	ResourceBundle bundle = null;

	try {
		bundle = ResourceBundle.getBundle(
			"com.sun.admin.pm.client.pmResources");
	} catch (MissingResourceException e) {
		Debug.fatal("Could not load pmResources file");
	}

	try {
    		s = bundle.getString(key);
	} catch (MissingResourceException e) {
		Debug.error("Missing: " + key);
	}

	Debug.message("Resource: " + key + " Value: " + s);

	if (s != null) {
		try {
		    keyvalue = s.charAt(0);
            	} catch (Exception x) {
		    Debug.error("Resource: " + key + " threw: " + x);
		}
        }

	return keyvalue;
    }

    public static void doLogin(
	pmTop mytop, JFrame frame) throws pmGuiException {

	pmLogin l;

	if (mytop.ns.getNameService().equals("nis") ||
		mytop.ns.getNameService().equals("ldap")) {

	    if (mytop.ns.getNameService().equals("nis")) {

		l = new pmLogin(
		    frame,
		    pmUtility.getResource("NIS.Authentication"),
		    pmUtility.getResource("Enter.NIS.authentication.data."),
		    mytop,
		    "NISAuthentication");

	    } else { // LDAP

		l = new pmLogin(
		    frame,
		    pmUtility.getResource("LDAP.Authentication"),
		    pmUtility.getResource("Enter.LDAP.authentication.data."),
		    mytop,
		    "LDAPAuthentication");
	    }

	    l.setVisible(true);

	    if ((l.getValue() != JOptionPane.OK_OPTION) &&
		 (l.getValue() != JOptionPane.CANCEL_OPTION)) {

			pmMessageDialog m = new pmMessageDialog(
				frame,
				pmUtility.getResource("Login.Failure"),
				pmUtility.getResource(
					"Request.cannot.be.completed."));
			m.setVisible(true);
			throw new pmGuiException
				("pmAccess: Cannot create Login screen");
	    }


	    if (l.getValue() == JOptionPane.CANCEL_OPTION) {
		    throw new pmUserCancelledException("User.Cancelled.Login");
	    } else {

		// Pass data to backend

		    // getPassword sends back untrimmed string that is invalid
		    // as a password as it's too long
		    String tmpp = new String(l.passwordField.getPassword());
		    mytop.ns.setPasswd(tmpp.trim());

		    if (mytop.ns.getNameService().equals("ldap")) {
			// setUser for binddn
			mytop.ns.setUser(l.dnField.getText());
			// setNameServiceHost overloaded for LDAP server name
			mytop.ns.setNameServiceHost(l.serverField.getText());
		    }

		    try {
			mytop.ns.checkAuth();
				Debug.message("doLogin():checkauth() OK");
		    } catch (Exception e) {
			Debug.warning("doLogin:checkAuth()exception " + e);
			throw new pmGuiException("Login.Authorization.Failed");
		    }
	    }


	// User has not put in printer or server
	} else {
	    pmMessageDialog m =
		new pmMessageDialog(
			frame,
			pmUtility.getResource("Login.Failure"),
			pmUtility.getResource("Request.cannot.be.completed."),
			mytop, "LoginFailed");

	    m.setVisible(true);
	    throw new pmGuiException("pmAccess: Cannot create Login screen");
	}

    }


}
