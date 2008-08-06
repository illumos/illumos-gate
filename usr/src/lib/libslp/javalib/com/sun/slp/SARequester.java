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

//  SARequester.java: Requester operations for SA.
//  Author:           James Kempf
//  Created On:       Thu Jan  8 14:59:41 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jan 28 15:33:33 1999
//  Update Count:     58
//

package com.sun.slp;

import java.io.*;
import java.util.*;

/**
 * The SARequester class implements the Advertiser interface.
 * It handles the request for the API. Registration is done
 * by calling into the loopback I/O so the SA server does
 * the registration.
 *
 * @author Erik Guttman, James Kempf
 */


class SARequester extends Object implements Advertiser {

    // For maintaining registrations that are LIFETIME_PERMANENT.

    private static PermSARegTable pregtable = null;

    private static SLPConfig config = null;

    private Locale locale;


    SARequester(Locale nlocale) {

	Assert.nonNullParameter(nlocale, "locale");

	// Initialize...

	getPermSARegTable();

	locale = nlocale;
    }

    // Initialize config, PermSARegTable.

    static PermSARegTable getPermSARegTable() {

	if (config == null) {
	    config = SLPConfig.getSLPConfig();
	}


	if (pregtable == null) {
	    pregtable = new PermSARegTable(config);

	}

	return pregtable;
    }

    //
    // Advertiser Interface implementation.
    //

    /**
     * Return the Locator's locale object. All requests are made in
     * this locale.
     *
     * @return The Locale object.
     */

    public Locale getLocale() {
	return locale;

    }

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
	throws ServiceLocationException {

	registerInternal(URL, serviceLocationAttributes, true);

    }

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
	throws ServiceLocationException {

	deregisterInternal(URL, null);

    }

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
	throws ServiceLocationException {

	registerInternal(URL, serviceLocationAttributes, false);

    }

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
	throws ServiceLocationException {

	if (attributeIds == null || attributeIds.size() <= 0) {
	    throw
		new IllegalArgumentException(
				config.formatMessage("null_or_empty_vector",
						     new Object[] {
				    "attributeIds"}));

	}

	deregisterInternal(URL, attributeIds);

    }

    //
    // Internal methods to do actual work.
    //

    /**
     * Takes care of registering a service.
     * @param URL    The service URL to register.
     * @param vAttrs A vector of ServiceLocationAttributes.
     * @param bFresh Informs whether this is to be a fresh registration or
     *               a reregistration.
     * @exception ServiceLocationException<br> If any errors occur during
     *		parsing out or on the remote agent.
     */

    private void registerInternal(ServiceURL URL,
				  Vector     vAttrs,
				  boolean    bFresh)
	throws ServiceLocationException {

	// Check parameters.

	Assert.nonNullParameter(URL, "URL");
	Assert.nonNullParameter(vAttrs,
				"serviceLocationAttributes");

	// Service agents are required to register in all the
	//  scopes they know.

	Vector vScopes = config.getSAConfiguredScopes();

	// Create registration message.

	CSrvReg srvreg =
	    new CSrvReg(bFresh,
			locale,
			URL,
			vScopes,
			vAttrs,
			null,
			null);

	// Register down the loopback.

	SrvLocMsg reply =
	    Transact.transactTCPMsg(config.getLoopback(), srvreg, true);

	// Handle any errors.

	handleError(reply);

	// Add registration for updating.

	// Create a reg to use for refreshing if the URL was permanently
	//  registered.

	if (URL.getIsPermanent()) {
	    CSrvReg srvReg =
		new CSrvReg(false,
			    locale,
			    URL,
			    vScopes,
			    new Vector(),
			    null,
			    null);

	    pregtable.reg(URL, srvReg);

	} else {
	    pregtable.dereg(URL);  // in case somebody registered permanent...

	}
    }



    /**
     * Takes care of deregistering a service or service attributes.
     *
     * @param URL The URL to deregister.
     * @param vAttrs The attribute tags, if any, to deregister.
     */

    private void deregisterInternal(ServiceURL URL,
				    Vector vAttrs)
	throws ServiceLocationException {

	Assert.nonNullParameter(URL, "URL");

	// Service agents are required to register in all the
	//  scopes they know.

	Vector vScopes = config.getSAConfiguredScopes();

	// If there are no attributes listed in the dereg, it removes the
	//  whole service.  In this case, purge it from the Permanent SA
	//  registration table.
	//

	if (vAttrs == null) {
	    pregtable.dereg(URL);

	}

	// Create deregistration message.

	CSrvDereg sdr =
	    new CSrvDereg(locale,
			  URL,
			  vScopes,
			  vAttrs,
			  null);

	// Register down the loopback.

	SrvLocMsg reply =
	    Transact.transactTCPMsg(config.getLoopback(), sdr, true);

	// Handle any errors.

	handleError(reply);
    }

    // Handle error returns.

    private void handleError(SrvLocMsg msg) throws ServiceLocationException {

	if (msg == null ||
	    ((msg.getHeader().functionCode == SrvLocHeader.SrvAck) == false)) {
	    throw new ServiceLocationException(
				ServiceLocationException.NETWORK_ERROR,
				"unexpected_ipc",
				new Object[0]);
	} else {
	    short ex =
		msg.getErrorCode();

	    if (ex != ServiceLocationException.OK) {
		throw new ServiceLocationException(ex,
						   "remote_error",
						   new Object[0]);
	    }
	}
    }

}
