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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  SunServerDATable.java: Server DA Table for Sun's client/SA server SLP.
//  Author:           James Kempf
//  Created On:       Wed May 20 09:58:46 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Mar  8 14:30:29 1999
//  Update Count:     79
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * SunServerDATable is a subclass class that provides the
 * implementation for DA storage on Solaris. As described in
 * the header for SunDATable, DA information is stored in the server's
 * SA table as the service type "directory-agent.sun"  with a
 * attribute, scopes. The attribute contains a list of scopes supported
 * by the DA. The service: URL of the registration contains the
 * DA address as the host, followed by the list of scopes as an attribute
 * in the URL part. An example is:
 *
 *   service:directory-agent.sun:// 199.200.200.5/scopes=eng, corp, freeb
 *
 * The scopes of the registration are the scopes provided as the Sun-specific
 * system property "sun.net.slp.SAOnlyScopes". By convention, this is
 * initialized to be the local machine name, but it may also include other
 * names.
 *
 * @author James Kempf
 */

class SunServerDATable extends ServerDATable {

    // DA boot timestamp.

    static final private String TIMESTAMP_ID =
	"424242SUN-TABLE-TIMESTAMP424242";

    // Address. Makes deletion easier.

    static final private String ADDRESS_ID = "424242SUN-TABLE-ADDRESS424242";

    private ServiceTable serviceTable = null;  // SA table for regs.
    private Vector saOnlyScopes = null;	       // Scopes for SA only.

    SunServerDATable() {

	// Get the service table.

	try {

	    serviceTable = ServiceTable.getServiceTable();

	} catch (ServiceLocationException ex) {

	}

	// Get the vector of SA scopes.

	saOnlyScopes = conf.getSAOnlyScopes();

	Assert.slpassert(saOnlyScopes.size() > 0,
		      "no_sa_scopes",
		      new Object[0]);

    }

    /**
     * Record a new DA in the service table.
     *
     * @param URL The DAAdvert URL.
     * @param scopes The scopes.
     * @param version DA version number.
     * @param spis SPIs this DA can support
     * @return The boot timestamp in the previous registration. Used
     *         to determine if registration is necessary. If an error occurs,
     *	       the returned value is negative. If the DA is new, the return
     *         value is the maximum long value. This will cause all
     *         registrations to be forwarded, because it is larger than any
     *         current time.
     */

    public synchronized long
	recordNewDA(ServiceURL url,
		    Vector scopes,
		    long timestamp,
		    int version,
		    Vector attrs,
		    String spis) {

	String addr = url.getHost();
	long formerTimestamp = -1L;

	// We record all DAs regardless of whether we support them or not,
	//  because a UA client may be using the user selectable scoping
	//  model and therefore may want to see them.

	Vector v = (Vector)scopes.clone();

	// Add the Sun attributes.

	ServiceLocationAttribute attr =
	    new ServiceLocationAttribute(SunDATable.SCOPES_ID, scopes);
	attrs.addElement(attr);

	Vector vals = new Vector();
	vals.addElement(Long.toString(timestamp));
	attr =
	    new ServiceLocationAttribute(SunServerDATable.TIMESTAMP_ID, vals);
	attrs.addElement(attr);

	vals = new Vector();
	vals.addElement(Integer.valueOf(version));
	attr = new ServiceLocationAttribute(SunDATable.VERSION_ID, vals);
	attrs.addElement(attr);

	vals = new Vector();
	vals.addElement(url.getHost());
	attr = new ServiceLocationAttribute(SunServerDATable.ADDRESS_ID, vals);
	attrs.addElement(attr);

	// Form the URL for the DA.

	ServiceURL adURL = formServiceTableDAURL(url, attrs);

	// Reach *around* the service table for registration, because
	//  we don't need a message. The service table abstraction
	//  is basically for decoding message objects, and we already
	//  have things in the internal form needed by the service store.

	ServiceStore store = serviceTable.store;

	try {

	    // First, get the boot time stamp if there.

	    Vector tags = new Vector();
	    tags.addElement(SunServerDATable.TIMESTAMP_ID);

	    Hashtable attrRec =
		store.findAttributes(adURL,
				     saOnlyScopes,
				     tags,
				     Defaults.locale);

	    Vector formerAttrs =
		(Vector)attrRec.get(ServiceStore.FA_ATTRIBUTES);

	    // If there, then get the old timestamp.

	    if (formerAttrs != null && !(formerAttrs.size() <= 0)) {

		// Get the timestamp into a long.

		attr = (ServiceLocationAttribute)formerAttrs.elementAt(0);
		vals = attr.getValues();
		String stamp = (String)vals.elementAt(0);

		try {

		    formerTimestamp = Long.parseLong(stamp.trim());

		} catch (NumberFormatException ex) {

		    Assert.slpassert(false,
				  "ssdat_number_format",
				  new Object[0]);

		}
	    }

	    // Now register the URL.

	    store.register(adURL,
			   attrs,
			   saOnlyScopes,
			   Defaults.locale,
			   null,
			   null);

	    // Keep track of this DAs supported SPIs
	    LinkedList spiList =
		AuthBlock.commaSeparatedListToLinkedList(spis);

	    // convert addr to an InetAddress for hashing
	    InetAddress inetAddr = null;
	    try {
		inetAddr = InetAddress.getByName(addr);
	    } catch (UnknownHostException e) {}

	    // If we didn't get the InetAddress, this DA will never be used
	    // anyway
	    if (addr != null) {
		daSPIsHash.put(inetAddr, spiList);
	    }

	} catch (ServiceLocationException ex) {
	    conf.writeLog("ssdat_register_error",
			  new Object[] {
		ex.getMessage(),
		    adURL,
		    saOnlyScopes});
	}

	return formerTimestamp;
    }

    /**
     * Remove a DA. The Sun-specific convention is used to deregister
     * the URL.
     *
     * @param address The host address of the DA, from its service URL.
     * @param scopes The scopes.
     * @return True if removed, false if not.
     */

    public synchronized boolean removeDA(InetAddress address, Vector scopes) {

	// Find URLs corresponding to this address.

	String query = "(" + ADDRESS_ID + "=" + address.getHostAddress() + ")";

	// Reach *around* the service table for dregistration, because
	//  we don't need a message. The service table abstraction
	//  is basically for decoding message objects, and we already
	//  have things in the internal form needed by the service store.

	ServiceStore store = serviceTable.store;

	try {

	    Hashtable das = returnMatchingDAs(query);

	    Enumeration daURLs = das.keys();

	    while (daURLs.hasMoreElements()) {
		ServiceURL adURL = (ServiceURL)daURLs.nextElement();
		store.deregister(adURL, saOnlyScopes, null);

	    }

	} catch (ServiceLocationException ex) {
	    conf.writeLog("ssdat_deregister_error",
			  new Object[] {
		ex.getMessage(),
		    address,
		    saOnlyScopes});

	    return false;
	}

	return true;

    }

    /**
     * Return a hashtable in ServiceTable.findServices() format (e.g.
     * URL's as keys, scopes as values) for DAs matching the query.
     *
     * @param query Query for DA attributes.
     */

    public synchronized Hashtable returnMatchingDAs(String query)
	throws ServiceLocationException {
	ServiceStore store = ServiceTable.getServiceTable().store;

	// Get DA records matching the query.

	Vector saOnlyScopes = conf.getSAOnlyScopes();

	Hashtable returns =
	    store.findServices(Defaults.SUN_DA_SERVICE_TYPE.toString(),
			       saOnlyScopes,
			       query,
			       Defaults.locale);

	// Return the hashtable of services v.s. scopes.

	return (Hashtable)returns.get(ServiceStore.FS_SERVICES);
    }

    /**
     * Return a hashtable of DA equivalence classes and multicast
     * scopes. Multicast scopes are stored in the special hashtable
     * key MULTICAST_KEY. Unicast DA equivalence classes are stored
     * under the key UNICAST_KEY. This implementation goes directly
     * to the service table in the SA server for the DA addresses.
     *
     * @param scopes Scope list for DAs needed.
     * @return Hashtable with DA addresses as keys and scopes to contact
     *         them with as values. Any scopes not associated with a
     *         DA come back stored under the key MULTICAST_KEY.
     *         Unicast DA equivalence classes are stored
     * 	     under the key UNICAST_KEY.
     */

    public synchronized Hashtable findDAScopes(Vector scopes)
	throws ServiceLocationException {

	// Formulate a query for the DAs.

	int i, n = scopes.size();
	StringBuffer buf = new StringBuffer();

	for (i = 0; i < n; i++) {
	    buf.append("(");
	    buf.append(SunDATable.SCOPES_ID);
	    buf.append("=");
	    buf.append((String)scopes.elementAt(i));
	    buf.append(")");
	}

	// Add logical disjunction if more than one element.

	if (i > 1) {
	    buf.insert(0, "(|");
	    buf.append(")");

	}

	// Add version number.

	if (i > 0) {
	    buf.insert(0, "(&");

	}

	buf.append("(");
	buf.append(SunDATable.VERSION_ID);
	buf.append("=");
	buf.append((Integer.valueOf(Defaults.version)).toString());
	buf.append(")");

	// Add closing paren if there were any scopes.

	if (i > 0) {
	    buf.append(")");

	}

	ServiceStore store = serviceTable.store;

	Hashtable returns =
	    store.findServices(Defaults.SUN_DA_SERVICE_TYPE.toString(),
			       saOnlyScopes,
			       buf.toString(),
			       Defaults.locale);

	Hashtable retRec = (Hashtable)returns.get(ServiceStore.FS_SERVICES);

	// Convert to a vector. Keys are the service: URLs.

	Enumeration en = retRec.keys();
	Vector ret = new Vector();
	Vector multiScopes = (Vector)scopes.clone();
	Vector attrTags = new Vector();

	attrTags.addElement(SunDATable.SCOPES_ID);

	while (en.hasMoreElements()) {
	    ServiceURL url = (ServiceURL)en.nextElement();
	    Vector urlScopes = (Vector)retRec.get(url);

	    // Get the scope attributes for this URL.

	    Hashtable attrRec =
		store.findAttributes(url,
				     urlScopes,
				     attrTags,
				     Defaults.locale);

	    Vector retAttrs = (Vector)attrRec.get(ServiceStore.FA_ATTRIBUTES);
	    String host = url.getHost();
	    Vector retScopes = null;
	    n = retAttrs.size();

	    for (i = 0; i < n; i++) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)retAttrs.elementAt(i);

		// Distinguish based on type. We assume the attributes are
		// prescreened when the URL was formed to make sure they're OK

		String id = attr.getId();
		Vector vals = attr.getValues();

		if (id.equals(SunDATable.SCOPES_ID)) {
		    retScopes = vals;

		}
	    }

	    // Add to equivalence class.

	    DATable.addToEquivClass(host, retScopes, ret);

	    // Filter scopes for any that might be multicast.

	    DATable.filterScopes(multiScopes, retScopes, false);

	}

	// Format the return.

	retRec.clear();

	if (multiScopes.size() > 0) {
	    retRec.put(DATable.MULTICAST_KEY, multiScopes);

	}

	if (ret.size() > 0) {
	    retRec.put(DATable.UNICAST_KEY, ret);

	}

	return retRec;
    }

    // Form a URL for the service table, from the DA URL and attributes.
    //  Attributes and scope have been prechecked for correctness.

    private ServiceURL formServiceTableDAURL(ServiceURL url, Vector attrs) {

	// Form up the URL part.

	StringBuffer buf = new StringBuffer();

	int i, n = attrs.size();

	for (i = 0; i < n; i++) {
	    ServiceLocationAttribute attr =
		(ServiceLocationAttribute)attrs.elementAt(i);

	    // If this is a URL attribute, then externalize and
	    //  put into URL.

	    String id = attr.getId();

	    if (id.equals(SunDATable.SCOPES_ID)) {
		String rep = "";

		try {
		    rep = attr.externalize();

		} catch (ServiceLocationException ex) {
		    conf.writeLog("ssdat_inter_attr_err",
				  new Object[] {attr, ex.getMessage()});
		    continue;

		}

		// Add semi if something already there.

		if (buf.length() > 0) {
		    buf.append(";");

		}

		// Remove parens before inserting.

		buf.append(rep.substring(1, rep.length()-1));

	    }
	}

	// Create the URL.

	ServiceURL daURL =
	    new ServiceURL(Defaults.SUN_DA_SERVICE_TYPE+
			   "://"+
			   url.getHost()+
			   "/"+
			   buf.toString(),
			   url.getLifetime());
	return daURL;

    }
}
