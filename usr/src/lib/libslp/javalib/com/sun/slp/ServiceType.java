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

//  ServiceType.java: Model a service type.
//  Author:           James Kempf
//  Created On:       Thu Apr  9 09:23:18 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Oct 19 15:43:18 1998
//  Update Count:     33
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The ServiceType class conceals the complex details of whether a
 * service type name is a simple URL scheme identifier, a service:
 * type, an abstract type or protocol type.
 *
 * @author James Kempf
 */

public class ServiceType extends Object implements Serializable {

    boolean isServiceURL = true;	// was it originally a service: type?
    private String type1 = "";	// scheme, abstract, or protocol.
    private String type2 = "";	// concrete, if type was abstract.
    private String na = "";	// naming authority.

    // For removing IANA.

    static final String IANA = "iana";

    /**
     * Create a service type object from the type name. The name may
     * take the form of any valid SLP service type name.
     *
     * @param t The type name.
     * @return The ServiceType object.
     * @exception IllegalArgumentException If the name is syntactically
     *					 incorrect.
     */

    public ServiceType(String t) throws IllegalArgumentException {

	parse(t);

    }

    /**
     * Return true if type name was from a service: URL.
     *
     * @return True if type name came from service: URL.
     */

    public boolean isServiceURL() {
	return isServiceURL;

    }

    /**
     * Return true if type name is for an abstract type.
     *
     * @return True if type name is for an abstract type.
     */

    public boolean isAbstractType() {
	return (type2.length() > 0);

    }

    /**
     * Return true if naming authority is default.
     *
     * @return True if naming authority is default.
     */

    public boolean isNADefault() {
	return (na.length() <= 0);

    }

    /**
     * Return the concrete service type name without naming authority.
     *
     * @return concrete type name.
     */

    public String getConcreteTypeName() {
	return type2;

    }

    /**
     * Return the principle type name, which is either the abstract
     * type name or the protocol name, without naming authority.
     *
     * @return Principle type name.
     */

    public String getPrincipleTypeName() {
	return type1;

    }

    /**
     * Return the fully formatted abstract type name, if it is an abstract
     * type, otherwise the empty string.
     */

    public String getAbstractTypeName() {
	if (isAbstractType()) {
	    return "service:" + type1 + (na.length() > 0 ? ("." + na):"");

	}
	return "";

    }

    /**
     * Return the naming authority name.
     *
     * @return Naming authority name.
     */

    public String getNamingAuthority() {
	return na;

    }

    /**
     *Validate a naming authority name.
     */

    static void validateTypeComponent(String name)
	throws ServiceLocationException {

	validateTypeComponentInternal(name, false);
    }

    // Validate, allowing '.' if allowDot is true.

    static private void
	validateTypeComponentInternal(String name, boolean allowDot)
	throws ServiceLocationException {
	int i, n = name.length();

	for (i = 0; i < n; i++) {
	    char c = name.charAt(i);

	    if ((Character.isLetterOrDigit(c) == false) &&
		(c != '+') && (c != '-')) {
		boolean throwIt = true;

		// If dot is allowed, don't throw it.

		if (allowDot && (c == '.')) {
		    throwIt = false;

		}

		if (throwIt) {
		    throw
			new IllegalArgumentException(
	SLPConfig.getSLPConfig().formatMessage("service_type_syntax",
					       new Object[] {name}));
		}
	    }
	}
    }

    // Two service type names are equal if they have the same
    //  types, naming authority, and same service: flag.

    public boolean equals(Object o) {

	if (o == this) {
	    return true;

	}

	if (!(o instanceof ServiceType)) {
	    return false;

	}

	ServiceType type = (ServiceType)o;

	return
	    (isServiceURL == type.isServiceURL) &&
	    type1.equals(type.type1) &&
	    type2.equals(type.type2) &&
	    na.equals(type.na);

    }

    // Format the service type name for output.

    public String toString() {

	return
	    (isServiceURL ? "service:" : "") +
	    type1 +
	    (na.length() > 0 ? ("." + na) : "") +
	    (type2.length() > 0 ? (":" + type2) : "");

    }

    // Return a hash code for the type.

    public int hashCode() {

	return type1.hashCode() +
	    na.hashCode() +
	    type2.hashCode() +
	    (isServiceURL ? Defaults.SERVICE_PREFIX.hashCode():0);

    }

    // Parse a service type name with optional naming authority.

    private void parse(String t) {
	StringTokenizer st = new StringTokenizer(t, ":.", true);

	try {

	    // This loop is a kludgy way to break out of the parse so
	    //  we only throw at one location in the code.

	    do {

		String tok = st.nextToken();

		if (tok.equals(":") || tok.equals(".")) {
		    break;  // error!

		}

		// Look for a nonservice: URL.

		if (!tok.equalsIgnoreCase(Defaults.SERVICE_PREFIX)) {
		    isServiceURL = false;

		    // Need to eat through all dots.

		    do {
			type1 = type1 + tok.toLowerCase();

			// Break when we run out of tokens.

			if (!st.hasMoreTokens()) {
			    break;

			}

			tok = st.nextToken();

		    } while (true);

		    // Check for disallowed characters. Allow '.'.

		    validateTypeComponentInternal(type1, true);

		    // There should be no more tokens.

		    if (st.hasMoreTokens()) {
			break; // error!

		    }

		    return; // done!

		}

		tok = st.nextToken();

		if (!tok.equals(":")) {
		    break; // error!

		}

		// Get the protocol or abstract type name.

		type1 = st.nextToken().toLowerCase();

		validateTypeComponent(type1);

		// From here on in, everything is optional, so be sure
		//  to check for no remaining tokens.

		if (!st.hasMoreTokens()) {
		    return;
		// done! It's a simple protocol type w.o. naming authority.

		}

		// It's either got a naming authority or is an abstract
		//  type (or both).

		tok = st.nextToken();

		// Check for naming authorithy.

		if (tok.equals(".")) {
		    tok = st.nextToken();

		    validateTypeComponent(tok);

		    if (!tok.equalsIgnoreCase(IANA)) {

			na = tok.toLowerCase();

		    } else {

			// Error to have IANA.

			break;

		    }

		    if (!st.hasMoreTokens()) {
			return;
		// done! It's a simple protocol type w. naming authority.

		    }

		    tok = st.nextToken();

		}

		// Should be at the separator to concrete type.

		if (!tok.equals(":")) {
		    break; // error!

		}

		tok = st.nextToken();

		// This is the concrete type name.

		validateTypeComponent(tok);

		type2 = tok.toLowerCase();

		// Should be no more tokens.

		if (st.hasMoreTokens()) {
		    break; // error!

		}

		return; // done!

	    } while (false);

	} catch (NoSuchElementException ex) {
	    throw
		new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("service_type_syntax",
						       new Object[] {t}));

	} catch (ServiceLocationException ex) {
	    throw
		new IllegalArgumentException(ex.getMessage());

	}

	throw
	    new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("service_type_syntax",
						       new Object[] {t}));

    }

}
