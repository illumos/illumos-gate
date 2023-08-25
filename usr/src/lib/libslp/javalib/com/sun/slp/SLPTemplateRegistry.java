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

//  SLPTemplateRegistry.java: Service object for registering a new service
//			  template.
//  Author:           James Kempf
//  Created On:       Tue May 27 15:04:35 1997
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jan  7 14:25:20 1999
//  Update Count:     134
//

package com.sun.slp;

import java.util.*;

/**
 * The SLPTemplateRegistry class registers and unregisters service templates,
 * looks up the template based on the service type name, and returns an
 * attribute verifier for the service.It subclasses the TemplateRegistry
 * abstract class.
 *
 * An slp-template URL has the following format:
 *
 *   service:slp-template:<document URL>;type=<service type>;
 *				          version=<version no.>;
 *					  language=<language locale>
 *
 * @author James Kempf
 *
 */

class SLPTemplateRegistry extends TemplateRegistry {

    /**
     * Attribute id for attribute describing service type name.
     * String, single valued attribute.
     */

    static final String SERVICE_ATTR_ID = "template-type";

    /**
     * Attribute id for attribute describing help text.
     * String, single valued, required attribute, .
     */

    static final String DESCRIPTION_ATTR_ID = "template-description";

    /**
     * Attribute id for attribute describing service version. The
     * version number is of the form ``n.m'', where n and m are integers.
     * String, single valued, required attribute.
     */

    static final String VERSION_ATTR_ID = "template-version";

    /**
     * Attribute id for attribute describing service URL url part grammer.
     * String, single valued, required attribute.
     */

    static final String SERVICE_URL_ATTR_ID = "template-url-syntax";

    /**
     * The service type name for the template type.
     */

    static final String TEMPLATE_SERVICE_TYPE = "service:slp-template";

    // The distinguished template registry object.

    private static TemplateRegistry registry = null;

    // Package private constructor for singleton pattern maintained
    // by the ServiceLocationManager.

    SLPTemplateRegistry() throws ServiceLocationException {

    }

    //
    // Public implementation.
    //

    /**
     * Register the new service.
     *
     * @param serviceType	Name of the service.
     * @param documentURL	URL of the template document.
     * @param languageLocale	Locale of the template langugae.
     * @param version		Version number of template document.
     * @exception ServiceLocationException Error code is
     *				    INVALID_REGISTRATION
     *					   if the service already exists or
     *					   the registration fails.
     *					   Throws
     *				    SYSTEM_ERROR
     *					   if the scope vector is null or
     *					   empty.
     *					   Throws
     *				    PARSE_ERROR
     *					   if an attribute is bad.
     * @exception IllegalArgumentException Thrown if any parameters are null.
     *
     */

    public void registerServiceTemplate(ServiceType serviceType,
					String documentURL,
					Locale languageLocale,
					String version)
	throws ServiceLocationException {

	// Check for illegal parameters.

	Assert.nonNullParameter(serviceType, "serviceType");

	Assert.nonNullParameter(documentURL, "documentURL");

	Assert.nonNullParameter(languageLocale, "language");

	Assert.nonNullParameter(version, "version");

	String language = languageLocale.getLanguage();

	if (language == null || language.length() <= 0) {
	    throw
		new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("template_lang_null",
						       new Object[] {
		    documentURL}));
	}

	String turl = null;

	try {

	    turl = findTemplateURL(serviceType,
				   languageLocale,
				   version);

	} catch (ServiceLocationException ex) {

	    // Ignore if language not supported, it just means there
	    //  isn't any.

	    if (ex.getErrorCode() !=
		ServiceLocationException.LANGUAGE_NOT_SUPPORTED) {
		throw ex;

	    }
	}

	// Throw an exception if it exists.

	if (turl != null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"template_already_registered",
				new Object[] {
		    documentURL,
			version,
			languageLocale});
	}

	// Construct attributes for the registration.

	Vector attributes = new Vector();

	// Add the service type name.

	Vector values = new Vector();
	values.addElement(serviceType.toString());
	ServiceLocationAttribute attr =
	    new ServiceLocationAttribute(SERVICE_ATTR_ID, values);

	attributes.addElement(attr);

	// Add the version.

	values = new Vector();
	values.addElement(version);
	attr =
	    new ServiceLocationAttribute(VERSION_ATTR_ID, values);

	attributes.addElement(attr);

	// Construct a service URL for the template.

	ServiceURL surl =
	    new ServiceURL(TEMPLATE_SERVICE_TYPE +
			   ":"+
			   documentURL+
			   ";"+
			   SERVICE_ATTR_ID+
			   "="+
			   serviceType+
			   ";"+
			   VERSION_ATTR_ID+
			   "="+
			   version,
			   ServiceURL.LIFETIME_MAXIMUM);


	// Do the registration.

	Advertiser serviceAgent =
	    ServiceLocationManager.getAdvertiser(languageLocale);

	if (serviceAgent == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.NOT_IMPLEMENTED,
				"no_advertiser",
				new Object[0]);
	}

	serviceAgent.register(surl, attributes);

	// Note that the assumption here is that the URL containing the
	//  path to the template document is written "somehow".
	//  It is up to the client to make sure that the template document
	//  has been written.

    }

    /**
     * Deregister the template for service type.
     *
     * @param serviceType	Name of service.
     * @param <i>languageLocale</i> Language locale of template.
     * @param <i>version</i> Version of the template, null for latest.
     * @exception ServiceLocationException Thrown if the deregistration
     *					  fails.
     * @exception IllegalArgumentException Thrown if the parameter is null.
     *
     */

    public void deregisterServiceTemplate(ServiceType serviceType,
					  Locale languageLocale,
					  String version)
	throws ServiceLocationException {

	// Check the parameter.

	Assert.nonNullParameter(serviceType, "serviceType");

	Assert.nonNullParameter(languageLocale, "languageLocale");

	// Get the template document URL for the service.

	ServiceURL turl = findVersionedURL(serviceType,
					   languageLocale,
					   version);

	// If there's no template, then throw an exception.

	if (turl == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"template_not_registered",
				new Object[] {
		    serviceType,
			version,
			languageLocale});
	}

	// Deregister in all scopes.

	Advertiser serviceAgent =
	    ServiceLocationManager.getAdvertiser(languageLocale);

	if (serviceAgent == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.NOT_IMPLEMENTED,
				"no_advertiser",
				new Object[0]);
	}

	// Deregister the service URL.

	serviceAgent.deregister(turl);

    }



    /**
     * Find the service URL for the service.
     *
     * @param serviceType		Name of service.
     * @param <i>languageLocale</i> Language locale of template.
     * @param <i>version</i> Version of the template, null for latest.
     * @return ServiceURL for the service template. If the service doesn't
     *		exist, returns null.
     * @exception ServiceLocationException Error code is
     *				    SYSTEM_ERROR
     *					   if the scope vector is null or
     *					   empty or if more than one
     *					   template URL is returned.
     * @exception IllegalArgumentException Thrown if any parameters are null.
     *
     */

    public String findTemplateURL(ServiceType serviceType,
				  Locale languageLocale,
				  String version)
	throws ServiceLocationException {

	// Check the parameter.

	Assert.nonNullParameter(serviceType, "serviceType");

	Assert.nonNullParameter(languageLocale, "languageLocale");

	ServiceURL turl = findVersionedURL(serviceType,
					   languageLocale,
					   version);

	// If nothing returned, then simply return.

	if (turl == null) {
	    return null;

	}

	// Form the document URL.

	ServiceType type = turl.getServiceType();
	String url = turl.toString();
	String abstractType = type.getAbstractTypeName();

	if (!abstractType.equals(TEMPLATE_SERVICE_TYPE)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_url_malformed",
				new Object[] {turl});

	}

	// Parse off the URL path.

	int idx = url.indexOf(";"+SERVICE_ATTR_ID+"=");

	if (idx == -1) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_url_malformed",
				new Object[] {turl});

	}

	int jdx = TEMPLATE_SERVICE_TYPE.length() + 1; // don't forget :!!!

	// Return the document URL.

	return url.substring(jdx, idx);
    }

    // Return a URL given a version and language locale.

    private ServiceURL findVersionedURL(ServiceType serviceType,
					Locale languageLocale,
					String version)
	throws ServiceLocationException {

	// Templates should be registered in all scopes. Look for them
	//  in all.

	Vector scopes = ServiceLocationManager.findScopes();

	// Set up query.

	ServiceLocationEnumeration results = null;
	String query = "(" + SERVICE_ATTR_ID + "=" + serviceType + ")";

	if (version != null) {
	    query = query + "(" + VERSION_ATTR_ID + "=" + version + ")";

	}

	query = "(&" + query + ")";

	// Get user agent for query.

	Locator userAgent =
	    ServiceLocationManager.getLocator(languageLocale);

	if (userAgent == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.NOT_IMPLEMENTED,
				"no_locator",
				new Object[0]);
	}

	try {
	    ServiceType type = new ServiceType(TEMPLATE_SERVICE_TYPE);

	    results =
		userAgent.findServices(type,
				       scopes,
				       query);

	} catch (ServiceLocationException ex) {

	    // If language not supported, it just means none there.

	    if (ex.getErrorCode() !=
		ServiceLocationException.LANGUAGE_NOT_SUPPORTED) {
		throw ex;

	    }

	}

	// If nothing came back, then return null.

	if (!results.hasMoreElements()) {
	    return null;

	}


	ServiceURL turl = null;
	float highest = (float)-1.0;

	// If there's more than one service of this type registered, then
	//  take highest version if version number was null.

	while (results.hasMoreElements()) {
	    ServiceURL surl = (ServiceURL)results.nextElement();
	    String urlPath = surl.getURLPath();

	    if (version == null) {

		// Get the version attribute from the URL.

		String token = ";"+VERSION_ATTR_ID+"=";

		int idx = urlPath.indexOf(token);

		if (idx == -1) { // ignore, there may be more...
		    continue;

		}

		urlPath =
		    urlPath.substring(idx+token.length(), urlPath.length());

		idx = urlPath.indexOf(";");

		if (idx == -1) { // ignore, there may be more...
		    continue;

		}

		String temversion = urlPath.substring(0, idx);
		float current = (float)0.0;

		// Convert to float.

		try {

		    current = Float.valueOf(temversion).floatValue();

		} catch (NumberFormatException ex) {

		    continue;  // ignore, there may be more...

		}

		// Identify if this is the highest version number so far.

		if (current > highest) {
		    turl = surl;
		}

	    } else {

		// If we found more than one, may be a problem.

		if (turl != null) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"template_multiple",
				new Object[] {
			    serviceType,
				version,
				languageLocale});
		}

		turl = surl;
	    }
	}

	return turl;
    }

    /**
     * Create an attribute verifier for the template document URL.
     *
     * @param documentURL A URL for the template document URL.
     * @return An attribute verifier for the service
     * @exception ServiceLocationException Throws
     *					  PARSE_ERROR
     *					  if any syntax errors
     *					  are encountered during parsing
     *					  of service's template definition.
     *					  Throws
     *					SYSTEM_ERROR
     *					  if URL parsing error occurs.
     *					  Throws ServiceLocationException
     *					  if any other errors occur.
     * @exception IllegalArgumentException Thrown if any parameters are null.
     *
     */

    public ServiceLocationAttributeVerifier attributeVerifier(
							String documentURL)
	throws ServiceLocationException {

	// Check the parameter.

	Assert.nonNullParameter(documentURL, "documentURL");

	// Create a URL attribute parser to parse the document.

	return new URLAttributeVerifier(documentURL);
    }

}
