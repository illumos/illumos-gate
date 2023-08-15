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

//  ServiceURL.java :  The service URL.
//  Author:           James Kempf, Erik Guttman
//

package com.sun.slp;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * The ServiceURL object models the SLP service URL. Both service: URLs
 * and regular URLs are handled by this class.
 *
 * @author James Kempf, Erik Guttman
 */

public class ServiceURL extends Object implements Serializable   {

    // Recognized transports.

    private final static String IPX = "ipx";
    private final static String AT = "at";

    /**
     * Indicates that no port information is required or was returned
     * for this service URL.
     */

    public static final int NO_PORT = 0;

    /**
     * No life time parameter is given.
     */

    public static final int LIFETIME_NONE    =  0;

    /**
     * Default lifetime, 3 hours.
     */

    public static final int LIFETIME_DEFAULT = 10800;

    /**
     * Maximum lifetime, approximately 18 hours.
     */

    public static final int LIFETIME_MAXIMUM = 0xFFFF;

    /**
     * Reregister periodically.
     */

    public static final int LIFETIME_PERMANENT = -1;

    // Maximum port size.

    static final int PORT_MAXIMUM = 0xFFFF;


    //
    // data fields
    //

    private ServiceType serviceType = null;
    private ServiceType originalServiceType = null;
    private String transport = "";
    private String host = "";
    private int port = NO_PORT;
    private String URLPath = "";
    private int lifetime = LIFETIME_DEFAULT;
    private boolean isPermanent = false;
    private boolean noDoubleSlash = false;

    /**
     * Construct a service URL object.
     *
     * @param URL		The service URL as a string.
     * @param iLifetime		The service advertisement lifetime.
     * @exception IllegalArgumentException Thrown if parse
     *				          errors occur in the
     *					  parameter.
     */

    public ServiceURL(String URL, int iLifetime)
	throws IllegalArgumentException {

	Assert.nonNullParameter(URL, "URL");

	if ((iLifetime > LIFETIME_MAXIMUM) ||
	   (iLifetime < LIFETIME_PERMANENT)) {
	    throw
		new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("lifetime_error",
						       new Object[0]));
	}

	checkURLString(URL);
	parseURL(URL);

	if (iLifetime == LIFETIME_PERMANENT) {
	    isPermanent = true;
	    iLifetime = LIFETIME_MAXIMUM;

	}

	lifetime = iLifetime;
    }

    //
    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    //

    /**
     * @return The service type name.
     */

    public ServiceType getServiceType() {
	return serviceType;

    }

    /**
     * Set service type and naming authority if this is not a service: URL.
     *
     * @param type The new ServiceType object.
     * @exception IllegalArgumentException If the service type name or
     *					 naming authority name is invalid.
     */

    public void setServiceType(ServiceType type) {
	if (!serviceType.isServiceURL()) {
	    serviceType = type;

	}

    }

    /**
     * @return The machine name or IP address.
     */

    public String getHost() {
	return host;

    }

    /**
     * @return The port number, if any.
     */

    public int getPort() {
	return port;

    }

    /**
     * @return The URL path description, if any.
     */

    public String getURLPath() {
	return URLPath;

    }

    /**
     * @return The service advertisement lifetime.
     */

    public int getLifetime() {
	return lifetime;

    }

    /**
     * Formats the service URL into standard URL form.
     *
     * @return Formatted string with the service URL.
     */

    public String toString() {  // Overrides Object.toString();

	return
	    originalServiceType.toString() +
	    ":/" + transport + (noDoubleSlash == false ? "/":"") +
	    host + (port != NO_PORT ? (":" + port) : "") +
	    URLPath;

    }

    public int hashCode() {
	return
	    serviceType.hashCode() +
	    transport.hashCode() +
	    host.hashCode() +
	    port +
	    URLPath.hashCode();
    }

    public boolean equals(Object obj) {

	if (obj == this) {
	    return true;

	}

	if (!(obj instanceof ServiceURL)) {
	    return false;
	}

	ServiceURL surl = (ServiceURL)obj;

	return
	    serviceType.equals(surl.serviceType) &&
	    transport.equals(surl.transport) &&
	    host.equals(surl.host) &&
	    (port == surl.port) &&
	    (noDoubleSlash == surl.noDoubleSlash) &&
	    URLPath.equals(surl.URLPath);

    }

    // Return permanent status.

    boolean getIsPermanent() {
	return isPermanent;

    }

    // Check URL characters for correctness.

    private void checkURLString(String s)
	throws IllegalArgumentException {
	for (int i = 0; i < s.length(); i++) {
	    char c = s.charAt(i);
	    // allowed by RFC1738
	    if (c == '/' || c == ':' || c == '-' || c == ':' ||
		c == '.' || c == '%' || c == '_' || c == '\'' ||
		c == '*' || c == '(' || c == ')' || c == '$' ||
		c == '!' || c == ',' || c == '+' || c == '\\') {
							// defer to Windows
		continue;

	    }

	    // reserved by RFC1738, and thus allowed, pg. 20
	    if (c == ';' || c == '@' || c == '?' || c == '&' || c == '=') {
		continue;

	    }

	    if (Character.isLetterOrDigit(c)) {
		continue;
	    }

	    SLPConfig conf = SLPConfig.getSLPConfig();

	    throw
		new IllegalArgumentException(
				conf.formatMessage("url_char_error",
						   new Object[] {
				    new Character(c)}));
	}
    }

    // Parse the incoming service URL specification.

    private void parseURL(String sURL)
	throws IllegalArgumentException {

	StringTokenizer st = new StringTokenizer(sURL, "/", true);

	try {

	    // This loop is a kludgy way to break out of the parse so
	    //  we only throw at one location in the code.

	    do {
		String typeName = st.nextToken();

		// First token must be service type name.

		if (typeName.equals("/")) {
		    break; // error!

		}

		// Check for colon terminator, not part of service
		// type name.

		if (!typeName.endsWith(":")) {
		    break; // error!

		}

		// Create service type, remove trailing colon.

		serviceType =
		    new ServiceType(typeName.substring(0,
						       typeName.length() - 1));
		originalServiceType = serviceType;

		// Separator between service type name and transport.

		String slash1 = st.nextToken();

		if (!slash1.equals("/")) {
		    break; // error!

		}

		String slash2 = st.nextToken();

		String sAddr = "";  // address...

		// Check for abstract type or alternate transport.

		if (!slash2.equals("/")) {

		    // If this is an abstract type, then we could have
		    //  something like: service:file-printer:file:/foo/bar.
		    //  This is OK. Also, if this is a non-service: URL,
		    //  something like file:/foo/bar is OK.

		    if (!serviceType.isServiceURL()) {
			sAddr = slash2;

			noDoubleSlash = true;

		    } else {

			// We only recognize IPX and Appletalk at this point.

			if (!slash2.equalsIgnoreCase(IPX) &&
			    !slash2.equalsIgnoreCase(AT)) {

			    // Abstract type is OK. We must check here because
			    //  something like
			    //  service:printing:lpr:/ipx/foo/bar
			    //  is allowed.

			    if (serviceType.isAbstractType()) {
				sAddr = slash2;

				noDoubleSlash = true;

			    } else {

				break;  // error!

			    }
			} else {

			    transport = slash2.toLowerCase();

			    // Check for separator between transport and host.

			    if (!st.nextToken().equals("/")) {
				break; // error!

			    }

			    sAddr = st.nextToken();
			}
		    }
		} else {

		    // Not abstract type, no alternate transport. Get host.

		    sAddr = st.nextToken();

		}

		if (sAddr.equals("/")) {// no host part
		    URLPath = "/" + st.nextToken("");
		    return; // we're done!

		}

		host = sAddr;

		// Need to check for port number if this is an IP transport.

		if (transport.equals("")) {
		    StringTokenizer tk = new StringTokenizer(host, ":");

		    host = tk.nextToken();

		    // Get port if any.

		    if (tk.hasMoreTokens()) {
			String p = tk.nextToken();

			if (tk.hasMoreTokens()) {
			    break; // error!

			}

			try {

			    port = Integer.parseInt(p);

			} catch (NumberFormatException ex) {
			    break; // error!

			}

			if (port <= 0 || port > PORT_MAXIMUM) {
			    break; // error!

			}
		    }
		}

		//
		// after this point we have to check if there is a token
		// remaining before we read it: It is legal to stop at any
		// point now.  Before all the tokens were required, so
		// missing any was an error.
		//
		if (st.hasMoreTokens() == false) {
					//  minimal url service:t:// a
		    return; // we're done!

		}

		String sSep  = st.nextToken();

		if (!sSep.equals("/")) {
		    break; // error!

		}

		// there is a URL path
		// URLPath is all remaining tokens
		URLPath = sSep;

		if (st.hasMoreTokens()) {
		    URLPath += st.nextToken("");

		}

		URLPath = URLPath.trim();

		return; // done!

	    } while (false); // done with parse.

	} catch (NoSuchElementException ex) {
	    throw
		new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("url_syntax_error",
						       new Object[] {sURL}));

	}

	// The only way to get here is if there was an error in the
	//  parse.

	throw
	    new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("url_syntax_error",
						       new Object[] {sURL}));

    }

}
