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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  ServiceLocationManager.java : The service locator object.
//  Author:           Erik Guttman
//

package com.sun.slp;

import java.util.*;
import java.io.*;
import java.lang.reflect.*;

/**
 * The ServiceLocationManager class provides entry to SLP services.
 * The ServiceLocationManager class uses static methods
 * to provide objects encapsulating the connection with the Service
 * Location facility. In addition, it provides access to known
 * scopes.
 *
 * @author Erik Guttman
 *
 */

abstract public class ServiceLocationManager extends Object {

    // Properties.

    protected static DATable dat = null;
    protected static SLPConfig config = null;

    protected static Hashtable locators = new Hashtable();
    protected static Hashtable advertisers = new Hashtable();
    protected static Class locatorClass = null;
    protected static Class advertiserClass = null;

    // Public interface

    /**
     * The property accessor for the Locator object. If user agent
     * functionality is not available, returns null.
     *
     * @param locale The Locale of the Locator object. Use null for default.
     * @return The Locator object.
     * @exception ServiceLocationException Thrown if the locator can't
     *					  be created.
     *
     */

    public static Locator getLocator(Locale locale)
	throws ServiceLocationException
    {

	if (locale == null) {
	    locale = config.getLocale();

	}

	String lang = locale.getLanguage();
	Locator locator = (Locator)locators.get(lang);

	if (locator == null) {

	    if (locatorClass == null) {
		String className =
		    System.getProperty("sun.net.slp.LocatorImpl");
		if (className == null) {
		    className = "com.sun.slp.UARequester";
		}
		locatorClass = getClass(className);
	    }

	    locator = (Locator)getInstance(locatorClass, locale);

	    if (locator != null) {
		locators.put(lang, locator);

	    }
	}

	return locator;
    }

    /**
     * The property accessor for the Advertiser object. If service agent
     * functionality is not available, returns null.
     *
     * @param locale The Locale of the Advertiser object. Use null for default.
     * @return The Advertiser object.
     * @exception ServiceLocationException Thrown if the locator can't
     *					  be created.
     *
     */

    public static Advertiser getAdvertiser(Locale locale)
	throws ServiceLocationException {

	if (locale == null) {
	    locale = config.getLocale();

	}

	String lang = locale.getLanguage();
	Advertiser advertiser = (Advertiser)advertisers.get(lang);

	if (advertiser == null) {

	    if (advertiserClass == null) {
		String className =
		    System.getProperty("sun.net.slp.AdvertiserImpl");
		if (className == null) {
		    className = "com.sun.slp.SARequester";
		}
		advertiserClass = getClass(className);
	    }

	    advertiser = (Advertiser)getInstance(advertiserClass, locale);

	    if (advertiser != null) {
		advertisers.put(lang, advertiser);

	    }
	}

	return advertiser;
    }

    /**
     * Returns a vector of known scope names.  It will include any
     * scopes defined in the configuration file and ensure that the
     * <i>order</i> of those scope strings is kept in the list of
     * scopes which is returned. This method enforces the constraint
     * that the default scope is returned if no other is available.
     *
     * @param typeHint Type to look for if SA advertisment required.
     * @return Vector containing Strings with scope names.
     */

    public static synchronized Vector findScopes()
	throws ServiceLocationException {

	Vector accessableScopes = null;

	// For the UA, return configured scopes if we have them.

	accessableScopes = config.getConfiguredScopes();

	// If no configured scopes, get discovered scopes from
	//  DA table.

	if (accessableScopes.size() <= 0) {
	    accessableScopes = dat.findScopes();

	    // If still none, perform SA discovery.

	    if (accessableScopes.size() <= 0) {
		accessableScopes = performSADiscovery();

		// If still none, then return default scope. The client won`t
		//  be able to contact anyone because there`s nobody out there.

		if (accessableScopes.size() <= 0) {
		    accessableScopes.addElement(Defaults.DEFAULT_SCOPE);

		}
	    }
	}

	return accessableScopes;
    }

    /**
     * Returns the maximum across all DAs of the min-refresh-interval
     * attribute.  This value satisfies the advertised refresh interval
     * bounds for all DAs, and, if used by the SA, assures that no
     * refresh registration will be rejected.  If no DA advertises a
     * min-refresh-interval attribute, a value of 0 is returned.
     *
     * @return The maximum min-refresh-interval attribute value.
     */

    public static int getRefreshInterval() throws ServiceLocationException {

	// Get the min-refresh-interval attribute values for all DA's from
	//  the server.

	Vector tags = new Vector();
	tags.addElement(Defaults.MIN_REFRESH_INTERVAL_ATTR_ID);

	// We don't simply do Locator.findAttributes() here because we
	//  need to contact the SA server directly.

	Vector saOnlyScopes = config.getSAOnlyScopes();

	CAttrMsg msg = new CAttrMsg(Defaults.locale,
				    Defaults.SUN_DA_SERVICE_TYPE,
				    saOnlyScopes,
				    tags);

	// Send it down the pipe to the IPC process. It's a bad bug
	//  if the reply comes back as not a CAttrMsg.

	CAttrMsg rply =
	    (CAttrMsg)Transact.transactTCPMsg(config.getLoopback(), msg, true);

	// Check error code.

	if (rply == null ||
	    rply.getErrorCode() != ServiceLocationException.OK) {
	    short errCode =
		(rply == null ?
		 ServiceLocationException.INTERNAL_SYSTEM_ERROR :
		 rply.getErrorCode());
	    throw
		new ServiceLocationException(errCode,
					     "loopback_error",
					     new Object[] {
		    Short.valueOf(errCode)});

	}

	// Sort through the attribute values to determine reply.

	int ri = 0;
	Vector attrs = rply.attrList;
	ServiceLocationAttribute attr =
	    (attrs.size() > 0 ?
	    (ServiceLocationAttribute)attrs.elementAt(0):
	    null);
	Vector values = (attr != null ? attr.getValues():new Vector());
	int i, n = values.size();

	for (i = 0; i < n; i++) {
	    Integer mri = (Integer)values.elementAt(i);
	    int mriv = mri.intValue();

	    if (mriv > ri) {
		ri = mriv;

	    }
	}

	return ri;
    }

    //
    // Private implementation.
    //

    // Return the requested class, or null if it can't be found.

    private static Class getClass(String name) {

	Class ret = null;

	try {

	    ret = Class.forName(name);

	} catch (ClassNotFoundException ex) {

	}

	return ret;

    }

    // Return an instance from the class.

    private static Object getInstance(Class cobj, Locale locale) {

	Object ret = null;

	if (cobj != null) {

	    try {
		Class[] paramClasses = {locale.getClass()};

		Constructor con = cobj.getDeclaredConstructor(paramClasses);

		Object[] params = {locale};

		ret = con.newInstance(params);

	    } catch (InstantiationException ex) {

	    } catch (IllegalAccessException ex) {

	    } catch (InvocationTargetException ex) {

	    } catch (NoSuchMethodException ex) {

	    }
	}

	return ret;
    }

    // Perform SA discovery, since no DA scopes found.

    private static Vector performSADiscovery()
	throws ServiceLocationException {

	// Get type hint if any.

	Vector hint = config.getTypeHint();

	// Format query.

	StringBuffer buf = new StringBuffer();
	int i, n = hint.size();

	for (i = 0; i < n; i++) {
	    buf.append("(");
	    buf.append(Defaults.SERVICE_TYPE_ATTR_ID);
	    buf.append("=");
	    buf.append(hint.elementAt(i).toString());

	}

	// Add logical disjunction if more than one element.

	if (i > 1) {
	    buf.insert(0, "(|");
	    buf.append(")");
	}

	// Form SA discovery request.

	CSrvMsg rqst = new CSrvMsg(config.getLocale(),
				   Defaults.SA_SERVICE_TYPE,
				   new Vector(),    // seeking scopes...
				   buf.toString());

	// Transact the advert request.

	Vector scopes =
	    Transact.transactActiveAdvertRequest(Defaults.SA_SERVICE_TYPE,
						 rqst,
						 null);
						// DA table not needed...

	return scopes;

    }

    // Initialize SLPConfig and DATable.

    static {

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	if (dat == null) {
	    dat = DATable.getDATable();

	}
    }
}
