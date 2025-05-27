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

//  UARequester.java: Requester operations for UA.
//  Author:           James Kempf
//  Created On:       Thu Jan  8 15:17:35 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Feb 22 13:47:06 1999
//  Update Count:     78
//

package com.sun.slp;

import java.util.*;

/**
 * The URequester class implements the Locator interface.
 * It handles the request for the API.  If any of the parameters
 * are missing, they will be supplied with a default value if
 * possible.  If a cached value may be supplied, it will be.
 * If no DA is present, and convergence is used to gather
 * results, these will be merged into one result.
 *
 * @author Erik Guttman, James Kempf
 */


class UARequester extends Object implements Locator {

    private static SLPConfig config = null;
    private static DATable dat = null;

    private Locale locale;

    UARequester(Locale nlocale) {

	Assert.nonNullParameter(nlocale, "locale");

	if (config == null) {
	    config = SLPConfig.getSLPConfig();
	}

	if (dat == null) {
	    dat = DATable.getDATable();
	}

	locale = nlocale;
    }

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
     * Return an enumeration of known service types for this scope and naming
     * authority.  Unless a proprietary or experimental service is being
     * discovered, the namingAuthority parameter should be the empty
     * string, "".
     *
     * @param NA	The naming authority, "" for default,
     *           '*' for any naming authority.
     * @param scopes	The SLP scopes of the types.
     * @return ServiceLocationEnumeration of ServiceType objects for
     *	      the service type names.
     * @exception IllegalArgumentException If any of the parameters are
     *					  null or syntactically incorrect.
     * @exception ServiceLocationException An exception is thrown if the
     *					  operation fails.
     */

    public synchronized ServiceLocationEnumeration
	findServiceTypes(String NA, Vector scopes)
	throws ServiceLocationException {

	Assert.nonNullParameter(NA, " NA");
	Assert.nonNullParameter(scopes, "scopes");

	// Formulate and send off messages.

	Vector msgs = createMessages(SrvLocHeader.SrvTypeRqst,
				     NA,
				     null,
				     null,
				     scopes);

	// Collate results.

	Vector ret = new Vector();
	int i, n = msgs.size();
	int max = config.getMaximumResults();

	for (i = 0; i < n; i++) {
	    CSrvTypeMsg msg = (CSrvTypeMsg)msgs.elementAt(i);

	    // Check for errors.

	    checkForError(msg, msgs);

	    Vector serviceTypes = msg.serviceTypes;

	    addUnique(serviceTypes, ret, max);

	}

	// Return.

	return new ServiceLocationEnumerator(ret);
    }

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

    public synchronized ServiceLocationEnumeration
	findServices(ServiceType type, Vector scopes, String query)
	throws ServiceLocationException {

	Assert.nonNullParameter(type, "type");
	Assert.nonNullParameter(scopes, "scopes");
	Assert.nonNullParameter(query, "query");

	// Formulate and send off messages.

	Vector msgs = createMessages(SrvLocHeader.SrvReq,
				     type,
				     query,
				     type,
				     scopes);

	// Collate results.

	Vector ret = new Vector();
	int i, n = msgs.size();
	int max = config.getMaximumResults();

	for (i = 0; i < n; i++) {
	    SrvLocMsg msg = (SrvLocMsg)msgs.elementAt(i);

	    // Check for errors.

	    checkForError(msg, msgs);

	    // Be sure to account for DAAdverts and SAAdverts.

	    Vector serviceURLs = null;

	    if (msg instanceof CSrvMsg) {
		serviceURLs = ((CSrvMsg)msg).serviceURLs;

	    } else if (msg instanceof CSAAdvert) {
		serviceURLs = new Vector();
		serviceURLs.addElement(((CSAAdvert)msg).URL);

	    } else if (msg instanceof CDAAdvert) {
		serviceURLs = new Vector();
		serviceURLs.addElement(((CDAAdvert)msg).URL);

	    }

	    addUnique(serviceURLs, ret, max);

	}

	// Return.

	return new ServiceLocationEnumerator(ret);
    }

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

    public synchronized ServiceLocationEnumeration
	findAttributes(ServiceURL URL, Vector scopes, Vector attributeIds)
	throws ServiceLocationException {

	Assert.nonNullParameter(URL, "URL");
	Assert.nonNullParameter(scopes, "scopes");
	Assert.nonNullParameter(attributeIds, "attributeIds");

	Vector msgs = createMessages(SrvLocHeader.AttrRqst,
				     URL,
				     attributeIds,
				     URL.getServiceType(),
				     scopes);

	// Check results.

	Vector ret = new Vector();
	int i, n = msgs.size();
	int max = config.getMaximumResults();

	// We only take the first message that came back and is OK.

	for (i = 0; i < n; i++) {
	    SrvLocMsg msg = (SrvLocMsg)msgs.elementAt(i);

	    // Check for errors.

	    checkForError(msg, msgs);

	    // Select out attribute list.

	    if (msg instanceof CAttrMsg) {
		ret = ((CAttrMsg)msg).attrList;

	    } else if (msg instanceof CSAAdvert) {

		// Need to check that URL matches.

		CSAAdvert smsg = (CSAAdvert)msg;

		if (!URL.equals(smsg.URL)) {
		    continue;

		}

		ret = smsg.attrs;

	    } else if (msg instanceof CDAAdvert) {

		// Need to check that URL matches.

		CDAAdvert smsg = (CDAAdvert)msg;

		if (!URL.equals(smsg.URL)) {
		    continue;

		}

		ret = smsg.attrs;
	    }

	    // Truncate, if return is larger than maximum.

	    if (ret.size() > max) {
		ret.setSize(max);

	    }

	    // Break out, we only need one.

	    break;

	}

	// Return.

	return new ServiceLocationEnumerator(ret);
    }

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

    public synchronized ServiceLocationEnumeration
	findAttributes(ServiceType type, Vector scopes, Vector attributeIds)
	throws ServiceLocationException {

	Assert.nonNullParameter(type, "URL");
	Assert.nonNullParameter(scopes, "scopes");
	Assert.nonNullParameter(attributeIds, "attributeIds");

	// Formulate and send off messages.

	Vector msgs = createMessages(SrvLocHeader.AttrRqst,
				     type,
				     attributeIds,
				     type,
				     scopes);
	// Collate results.

	Vector ret = new Vector();
	int i, n = msgs.size();
	int max = config.getMaximumResults();
	Hashtable ht = new Hashtable();

	for (i = 0; i < n && ret.size() < max; i++) {
	    SrvLocMsg msg = (SrvLocMsg)msgs.elementAt(i);

	    // Check for errors.

	    checkForError(msg, msgs);

	    Vector attrList = null;

	    // Get the instance variable.

	    if (msg instanceof CAttrMsg) {
		attrList = ((CAttrMsg)msg).attrList;

	    } else if (msg instanceof CSAAdvert) {
		attrList = ((CSAAdvert)msg).attrs;

	    } else if (msg instanceof CDAAdvert) {
		attrList = ((CDAAdvert)msg).attrs;

	    }

	    // Merge any duplicates.

	    int j, m = attrList.size();

	    for (j = 0; j < m; j++) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)attrList.elementAt(j);

		ServiceLocationAttribute.mergeDuplicateAttributes(attr,
								  ht,
								  ret,
								  true);

		if (ret.size() >= max) {
		    break;

		}
	    }
	}

	// Return.

	return new ServiceLocationEnumerator(ret);
    }

    // Execute the message request, returning messages.

    private Vector
	createMessages(int msgType,
		       Object t1,
		       Object t2,
		       ServiceType type,
		       Vector scopes)
	throws ServiceLocationException {

	// Validate, lower case scopes.

	DATable.validateScopes(scopes, locale);

	SrvLocMsg multiMsg = null;
	SrvLocMsg uniMsg = null;
	Vector daAddresses = null;
	Vector multiCastScopes = null;

	// Get the hashtable of unicast DA addresses and multicast scopes.

	Hashtable daRecords = dat.findDAScopes(scopes);

	// Get multicast scopes and DA addresses.

	multiCastScopes =
	    (Vector)daRecords.get(DATable.MULTICAST_KEY);

	daAddresses =
	    (Vector)daRecords.get(DATable.UNICAST_KEY);

	// Special case for service request and attribute request
	//  if the user is looking for a special SLP type.

	if (((msgType == SrvLocHeader.SrvReq) ||
	    (msgType == SrvLocHeader.AttrRqst)) &&
	    (type.equals(Defaults.DA_SERVICE_TYPE) ||
	    type.equals(Defaults.SA_SERVICE_TYPE))) {

	    multiCastScopes = scopes;
	    daAddresses = null;

	    // Get query. If an attribute request, then the user
	    //  needs to sort out the attributes.

	    String query = "";

	    if (msgType == SrvLocHeader.SrvReq) {
		query = (String)t2;

	    }

	    multiMsg = new CSrvMsg(locale, type, multiCastScopes, query);

	} else {

	    // Handle a regular message.

	    // Multicast scopes are all scopes not supported by any DA.

	    if (multiCastScopes != null) {

		switch (msgType) {

		case SrvLocHeader.SrvTypeRqst:
		    multiMsg =
			new CSrvTypeMsg(locale, (String)t1, multiCastScopes);
		    break;

		case SrvLocHeader.SrvReq:
		    multiMsg =
			new CSrvMsg(locale, type, multiCastScopes, (String)t2);
		    break;

		case SrvLocHeader.AttrRqst:

		    if (t1 instanceof ServiceURL) {
			multiMsg =
			    new CAttrMsg(locale,
					 (ServiceURL)t1,
					 multiCastScopes,
					 (Vector)t2);

		    } else {
			multiMsg =
			    new CAttrMsg(locale,
					 type,
					 multiCastScopes,
					 (Vector)t2);

		    }
		}
	    }

	    // Unicast only requires a single message because the DAs will
	    //  ignore any scopes they do not support, just as long as
	    //  they support one of them.

	    if (daAddresses != null) {
		switch (msgType) {

		case SrvLocHeader.SrvTypeRqst:
		    uniMsg =
			new CSrvTypeMsg(locale, (String)t1, scopes);
		    break;

		case SrvLocHeader.SrvReq:
		    uniMsg =
			new CSrvMsg(locale, type, scopes, (String)t2);
		    break;

		case SrvLocHeader.AttrRqst:

		    if (t1 instanceof ServiceURL) {
			uniMsg =
			    new CAttrMsg(locale,
					 (ServiceURL)t1,
					 scopes,
					 (Vector)t2);

		    } else {
			uniMsg =
			    new CAttrMsg(locale,
					 type,
					 scopes,
					 (Vector)t2);

		    }

		}
	    }
	}

	// Send off messages, return results.

	return Transact.transactUA(daAddresses,
				   uniMsg,
				   multiMsg,
				   config.getMulticastAddress());
    }

    // Check message for error code.

    private static void
	checkForError(SrvLocMsg msg, Vector v)
	throws ServiceLocationException {
	int err = msg.getErrorCode();

	if (err != ServiceLocationException.OK) {
	    if (v.size() == 1) {
		config.writeLog("single_exception",
				new Object[] {
		    Integer.valueOf(err)});
		throw
		    new ServiceLocationException((short)err,
						 "remote_error",
						 new Object[] {});
	    } else {
		config.writeLog("multiple_exception",
				new Object[] {
		    Integer.valueOf(err)});
	    }
	}
    }

    // Process the incoming vector, adding any unique returns.

    private static void addUnique(Vector incoming, Vector returns, int max) {

	int i, n = incoming.size();

	for (i = 0; i < n; i++) {
	    Object o = incoming.elementAt(i);

	    if (!returns.contains(o) && returns.size() < max) {
		returns.addElement(o);

	    }
	}
    }

}
