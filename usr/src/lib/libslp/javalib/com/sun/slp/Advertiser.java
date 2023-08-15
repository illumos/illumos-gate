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

//  ServiceAgent.java: Interface for the SLP Service Agent operations
//  Author:           James Kempf
//  Created On:       Mon Jul  7 09:05:40 1997
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jan  7 14:17:12 1999
//  Update Count:     16
//

package com.sun.slp;

import java.util.*;

/**
 * The Advertiser interface allows clients to register new service
 * instances with SLP and to change the attributes of existing services.
 *
 * @see ServiceLocationManager
 *
 * @author James Kempf, Erik Guttman
 */

public interface Advertiser {

    /**
     * Return the Advertiser's locale object.
     *
     * @return The Locale object.
     */

    Locale getLocale();

    /**
     * Register a new service with the service location protocol in
     * the Advertiser's locale.
     *
     * @param URL	The service URL for the service.
     * @param serviceLocationAttributes A vector of ServiceLocationAttribute
     *				       objects describing the service.
     * @exception ServiceLocationException An exception is thrown if the
     *					  registration fails.
     * @exception IllegalArgumentException A  parameter is null or
     *					  otherwise invalid.
     *
     */

    public void register(ServiceURL URL,
			 Vector serviceLocationAttributes)
	throws ServiceLocationException;

    /**
     * Deregister a service with the service location protocol.
     * This has the effect of deregistering the service from <b>every</b>
     * Locale and scope under which it was registered.
     *
     * @param URL	The service URL for the service.
     * @exception ServiceLocationException An exception is thrown if the
     *					  deregistration fails.
     */

    public void deregister(ServiceURL URL)
	throws ServiceLocationException;

    /**
     * Add attributes to a service URL in the locale of the Advertiser.
     *
     * Note that due to SLP v1 update semantics, the URL will be registered
     * if it is not already.
     *
     *
     * @param URL	The service URL for the service.
     * @param serviceLocationAttributes A vector of ServiceLocationAttribute
     *				       objects to add.
     * @exception ServiceLocationException An exception is thrown if the
     *					  operation fails.
     */

    public void addAttributes(ServiceURL URL,
			      Vector serviceLocationAttributes)
	throws ServiceLocationException;

    /**
     * Delete the attributes from a service URL in the locale of
     * the Advertiser. The deletions are made for all scopes in
     * which the URL is registered.
     *
     *
     * @param URL	The service URL for the service.
     * @param attributeIds A vector of Strings indicating
     *			  the attributes to remove.
     * @exception ServiceLocationException An exception is thrown if the
     *					  operation fails.
     */

    public void deleteAttributes(ServiceURL URL,
				 Vector attributeIds)
	throws ServiceLocationException;
}
