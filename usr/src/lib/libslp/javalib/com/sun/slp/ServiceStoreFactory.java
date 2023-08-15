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

//  ServiceStoreFactory.java: Factory for creating ServiceStore objects.
//  Author:           James Kempf
//  Created On:       Fri Apr 17 12:14:12 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Jan  4 15:26:34 1999
//  Update Count:     34
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The ServiceStoreFactory provides a way to obtain a ServiceStore
 * object. The exact implementation will depend on how the
 * DA/slpd is configured. It could be an in-memory database,
 * a connection to an LDAP server, or a persistent object
 * database.
 *
 * @author James Kempf
 */

class ServiceStoreFactory extends Object {

    private static final String DEFAULT_SERVICE_STORE =
	"com.sun.slp.ServiceStoreInMemory";

    private static final String SERVICE_STORE_PROPERTY =
	"sun.net.slp.serviceStoreClass";

    // Comment characters for deserialization.

    final private static char COMMENT_CHAR1 = '#';
    final private static char COMMENT_CHAR2 = ';';

    // Character for URL list separator.

    final private static String URL_LIST_SEP = ", ";

    // Identifies scopes pseudo-attribute.

    final private static String SCOPES_ATTR_ID = "scopes";

    /**
     * Return the ServiceStore for the SLP agent.
     *
     * @return An object supporting the ServiceStore interface.
     * @exception ServiceLocationException Thrown
     *			if the ServiceStore object can't be
     *			created or if the
     *			class implementing the ServiceStore required
     *			a network connnection (for example, an LDAP
     *			server) and the connection couldn't be made.
     */

    static ServiceStore createServiceStore()
	throws ServiceLocationException {

	return createServiceStoreFromProperty(SERVICE_STORE_PROPERTY);

    }

    // Create the appropriate ServiceStore object from the property.

    private static ServiceStore
	createServiceStoreFromProperty(String property)
	throws ServiceLocationException {

	Properties props = System.getProperties();
	String storeClassName =
	    props.getProperty(property,
			      DEFAULT_SERVICE_STORE);
	Class storeClass = null;

	try {

	    storeClass = Class.forName(storeClassName);

	} catch (ClassNotFoundException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"ssf_no_class",
				new Object[] {storeClassName});
	}

	ServiceStore store = null;

	try {

	    store = (ServiceStore)storeClass.newInstance();

	} catch (InstantiationException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"ssf_inst_ex",
				new Object[] {
		    storeClassName,
			ex.getMessage()});

	} catch (IllegalAccessException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"ssf_ill_ex",
				new Object[] {
		    storeClassName,
			ex.getMessage()});

	} catch (ClassCastException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"ssf_class_cast",
				new Object[] {storeClassName});
	}

	return store;
    }

    /**
     * Deserialize a service store from the open stream.
     *
     * @param is The object input stream for the service store.
     * @return ServiceStore deserialized from the stream.
     * @exception ServiceLocationException If anything goes
     *				wrong with the deserialization.
     */

    static ServiceStore deserializeServiceStore(BufferedReader is)
	throws ServiceLocationException {

	ServiceStore ss = new ServiceStoreInMemory();

	try {

	    deserialize(is, ss);

	} catch (IOException ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"ssf_io_deser",
				new Object[] {ex.getMessage()});

	}

	return ss;
    }

    // Read the service store in the standard format from the input

    private static void deserialize(BufferedReader in, ServiceStore store)
	throws IOException, ServiceLocationException {

	SLPConfig conf = SLPConfig.getSLPConfig();
	int linecount = 0;
	int scopeLinenum = 0;

	// Parse input file until no bytes left.

	while (in.ready()) {
	    linecount++;
	    String line = in.readLine().trim();

	    // Skip any empty lines at this level.

	    if (line.length() <= 0) {
		continue;

	    }

	    char cc = line.charAt(0);

	    // If initial character is "#" or ";", ignore the line.
	    //  It's a comment. Also if the line is empty.

	    if (cc == COMMENT_CHAR1 ||
		cc == COMMENT_CHAR2) {
		continue;
	    }

	    // At this level, the line must be a URL registration,
	    //  with format:
	    //
	    // service-url ", " language ", " lifetime [ ", " type ]
	    //
	    //
	    //  We allow arbitrary whitespace around commas.

	    StringTokenizer tk = new StringTokenizer(line, URL_LIST_SEP);
	    String surl = null;
	    String slang = null;
	    String slifetime = null;
	    String sType = null;

	    if (tk.hasMoreTokens()) {
		surl = tk.nextToken().trim();

		if (tk.hasMoreTokens()) {
		    slang = tk.nextToken().trim();

		    if (tk.hasMoreTokens()) {
			slifetime = tk.nextToken().trim();

			if (tk.hasMoreTokens()) {
			    sType = tk.nextToken().trim();

			    if (tk.hasMoreTokens()) {
				slang = null;
					// should be nothing more on the line.

			    }
			}
		    }
		}
	    }

	    // Check for errors.

	    if (surl == null || slifetime == null || slang == null) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"ssf_not_valid_url",
				new Object[] {line});
	    }

	    // Create the service: URL.

	    Locale locale = SLPConfig.langTagToLocale(slang);
	    ServiceURL url = null;

	    try {

		int lifetime = Integer.parseInt(slifetime);

		// If lifetime is maximum, then set to LIFETIME_PERMANENT.

		if (lifetime == ServiceURL.LIFETIME_MAXIMUM) {
		    lifetime = ServiceURL.LIFETIME_PERMANENT;

		}

		url = new ServiceURL(surl, lifetime);

		if (sType != null) {

		    // Check if it's OK for this service URL.

		    ServiceType utype = url.getServiceType();

		    if (utype.isServiceURL()) {
			conf.writeLog("ssf_set_servc_err",
				      new Object[] {
			    surl,
				utype});

		    } else {
			ServiceType t = new ServiceType(sType);

			if (!t.isServiceURL() &&
			    !t.equals(url.getServiceType())) {
			    url.setServiceType(t);

			}

		    }
		}

	    } catch (NumberFormatException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"ssf_not_valid_lifetime",
				new Object[] {
			slifetime, new Integer(linecount)});

	    } catch (IllegalArgumentException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"ssf_syntax_err",
				new Object[] {
			ex.getMessage(), new Integer(linecount)});

	    }

	    // Get attributes. Format should be:
	    //
	    //      attr-line    = attr-assign | keyword
	    //	attr-assign  = attr-id "=" attrval-list
	    //	keyword      = attr-id
	    //	attrval-list = attrval | attrval ", " attrval-list

	    Vector attrs = new Vector();
	    Hashtable ht = new Hashtable();
	    ServiceLocationAttribute scopeAttr = null;
	    boolean firstLine = true;

	    try {
		while (in.ready()) {
		    linecount++;
		    line = in.readLine();

		    // Empty line indicates we're done with attributes.

		    if (line.length() <= 0) {
			break;
		    }

		    // Format the line for creating. Check whether it's a
		    // keyword or not.

		    if (line.indexOf("=") != -1) {
			line = "(" + line + ")";

		    }

		    // Create the attribute from the string.

		    ServiceLocationAttribute attr =
			new ServiceLocationAttribute(line, false);

		    // If this is the scope attribute, save until later.

		    if (firstLine) {
			firstLine = false;

			if (attr.getId().equalsIgnoreCase(SCOPES_ATTR_ID)) {
			    scopeAttr = attr;
			    continue; // do NOT save as a regular attribute.

			}
		    }

		    ServiceLocationAttribute.mergeDuplicateAttributes(attr,
								      ht,
								      attrs,
								      false);

		}
	    } catch (ServiceLocationException e) {
		// tack on the line count
		e.makeAddendum(" (line " + linecount + ")");
		throw e;

	    }

	    Vector scopes = null;

	    // Use scopes we've been configured with if none.

	    if (scopeAttr == null) {
		scopes = conf.getSAConfiguredScopes();

	    } else {

		scopes = (Vector)scopeAttr.getValues();

		try {
		    // Unescape scope strings.

		    SLPHeaderV2.unescapeScopeStrings(scopes);

		    // Validate, lower case scope names.

		    DATable.validateScopes(scopes, locale);

		} catch (ServiceLocationException e) {
		    e.makeAddendum(" (line " + scopeLinenum + ")");
		    throw e;
		}

	    }

	    // We've got the attributes, the service URL, scope, and
	    //  locale, so add a record. Note that any crypto is
	    //  added when the registration is actually done.

	    store.register(url, attrs, scopes, locale, null, null);

	    // Create a CSrvReg for forwarding
	    CSrvReg creg = new CSrvReg(true, locale, url, scopes,
				       attrs, null, null);

	    ServerDATable daTable = ServerDATable.getServerDATable();
	    daTable.forwardSAMessage(creg, conf.getLoopback());

	}
    }

    // Write the service store in the standard format to the output
    // stream.

    static void serialize(BufferedWriter out, ServiceStore store)
	throws IOException, ServiceLocationException {

	Enumeration recs = store.getServiceRecordsByScope(null);

	while (recs.hasMoreElements()) {
	    ServiceStore.ServiceRecord rec =
		(ServiceStore.ServiceRecord)recs.nextElement();
	    ServiceURL url = rec.getServiceURL();
	    String surl = url.toString();
	    Vector attrs = (Vector)rec.getAttrList().clone();
	    Locale locale = rec.getLocale();
	    Vector scopes = rec.getScopes();
	    StringBuffer line = new StringBuffer();

	    // Compose the registration line.

	    line.append(surl);
	    line.append(", ");
	    line.append(SLPConfig.localeToLangTag(locale));
	    line.append(", ");
	    line.append(Integer.toString(url.getLifetime()));

	    // Put out the service type and naming authority if the
	    //  URL is not a service URL.

	    if (!surl.startsWith(Defaults.SERVICE_PREFIX)) {
		ServiceType type = url.getServiceType();

		line.append(", ");
		line.append(type.toString());

	    }

	    // Write out line.

	    out.write(line.toString(), 0, line.length());
	    out.newLine();

	    // Zero line buffer.

	    line.setLength(0);

	    // Insert a scope attribute, if the scope isn't simply "DEFAULT".

	    if (scopes.size() > 1 &&
		!Defaults.DEFAULT_SCOPE.equals((String)scopes.elementAt(0))) {
		attrs.insertElementAt(
				new ServiceLocationAttribute(SCOPES_ATTR_ID,
							     scopes),
				0);
	    }

	    // Write out the attributes.

	    int i, n = attrs.size();

	    for (i = 0; i < n; i++) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)attrs.elementAt(i);
		Vector vals = attr.getValues();

		line.append(
		ServiceLocationAttribute.escapeAttributeString(attr.getId(),
							       false));
		// Add the escaped values.

		if (vals != null) {

		    line.append("=");

		    int j, m = vals.size();

		    for (j = 0; j < m; j++) {
			Object v = vals.elementAt(j);

			if (j > 0) {
			    line.append(", ");

			}

			line.append(ServiceLocationAttribute.escapeValue(v));

		    }
		}

		out.write(line.toString(), 0, line.length());
		out.newLine();

		// Zero out string buffer.

		line.setLength(0);

	    }

	    // End of registration.

	    out.newLine();
	}

	out.flush();
    }

}
