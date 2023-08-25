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

//  UserAgent.java:   Interface for the SLP User Agent operations
//  Author:           James Kempf
//  Created On:       Mon Jul  7 09:15:56 1997
//  Last Modified By: James Kempf
//  Last Modified On: Wed May 13 17:46:29 1998
//  Update Count:     17
//

package com.sun.slp;

import java.util.*;

/**
 * The Locator interface allows clients to query SLP for existing
 * services, scopes, and service instances, and to query about attributes
 * of a particular service instance.
 *
 * @see ServiceLocationManager
 *
 * @author James Kempf, Erik Guttman
 */

public interface Locator {

    /**
     * Return the Locator's locale object.
     *
     * @return The Locale object.
     */

    Locale getLocale();

    /**
     * Return an enumeration of known service types for this scope and naming
     * authority.  Unless a proprietary or experimental service is being
     * discovered, the namingAuthority parameter should be the empty
     * string, "".
     *
     * @param namingAuthority	The naming authority, "" for default,
     *                           '*' for any naming authority.
     * @param scopes	The SLP scopes of the types.
     * @return ServiceLocationEnumeration of ServiceType objects for
     *	      the service type names.
     * @exception IllegalArgumentException If any of the parameters are
     *					  null or syntactically incorrect.
     * @exception ServiceLocationException An exception is thrown if the
     *					  operation fails.
     */

    public ServiceLocationEnumeration findServiceTypes(String namingAuthority,
						       Vector scopes)
	throws ServiceLocationException;

    /**
     * Return an enumeration of ServiceURL objects for services matching
     * the query. The services are returned from the locale of the
     * locator.
     *
     * @param type	The type of the service (e.g. printer, etc.).
     * @param scopes	The SLP scopes of the service types.
     * @param query		A string with the SLP query.
     * @return ServiceLocationEnumeration of ServiceURL objects for
     *	      services matching the
     *         attributes.
     * @exception ServiceLocationException An exception is returned if the
     *					  operation fails.
     * @see ServiceURL
     */

    public ServiceLocationEnumeration findServices(ServiceType type,
						   Vector scopes,
						   String query)
	throws ServiceLocationException;

    /**
     * Return the attributes for the service URL, using the locale
     * of the locator.
     *
     * @param URL	The service URL.
     * @param scopes	The SLP scopes of the service.
     * @param attributeIds A vector of strings identifying the desired
     *			  attributes. A null value means return all
     *			  the attributes.  <b>Partial id strings</b> may
     *                     begin with '*' to match all ids which end with
     *                     the given suffix, or end with '*' to match all
     *                     ids which begin with a given prefix, or begin
     *                     and end with '*' to do substring matching for
     *                     ids containing the given partial id.
     * @return ServiceLocationEnumeration of ServiceLocationAttribute
     *         objects matching the ids.
     * @exception ServiceLocationException An exception is returned if the
     *					  operation fails.
     * @exception IllegalArgumentException If any of the parameters are
     *					  null or syntactically incorrect.
     * @see ServiceLocationAttribute
     *
     */

    public ServiceLocationEnumeration findAttributes(ServiceURL URL,
						     Vector scopes,
						     Vector attributeIds)
	throws ServiceLocationException;

    /**
     * Return all attributes for all service URL's having this
     * service type in the locale of the Locator.
     *
     * @param type The service type.
     * @param scopes	The SLP scopes of the service type.
     * @param attributeIds A vector of strings identifying the desired
     *			  attributes. A null value means return all
     *			  the attributes.  <b>Partial id strings</b> may
     *                     begin with '*' to match all ids which end with
     *                     the given suffix, or end with '*' to match all
     *                     ids which begin with a given prefix, or begin
     *                     and end with '*' to do substring matching for
     *                     ids containing the given partial id.
     * @return ServiceLocationEnumeration of ServiceLocationAttribute
     *         objects matching the ids.
     * @exception ServiceLocationException An exception is returned if the
     *					  operation fails.
     * @exception IllegalArgumentException If any of the parameters are
     *					  null or syntactically incorrect.
     * @see ServiceLocationAttribute
     *
     */

    public ServiceLocationEnumeration findAttributes(ServiceType type,
						     Vector scopes,
						     Vector attributeIds)
	throws ServiceLocationException;


}
