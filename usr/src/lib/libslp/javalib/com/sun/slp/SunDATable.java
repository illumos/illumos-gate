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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  SunDATable.java: A DATable implementation that uses the IPC connection.
//  Author:           James Kempf
//  Created On:       Mon May 11 15:00:23 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Mar 11 15:00:58 1999
//  Update Count:     71
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * The SunDATable class uses the IPC connection to obtain DA information
 * from the SA server. By convention, the SA server answers service
 * requests for the service type "directory-agent.sun" and including
 * a filter for the scopes formatted as:
 *
 *   "(&(|(scopes=<scope1>)(scopes=<scope2>)(scopes=<scope3>)...)(version=2))"
 *
 * with a collection of URLs that fit the request. The scope of the
 * request is the hostname of the local machine, which will not be
 * forwarded to any DAs. The URLs contain the
 * DA IP address in the host field and a list of scopes in the URL
 * part in the form of an attribute value assignment, i.e.:
 *
 *   service:directory-agent.sun:// 199.200.200.5/scopes=eng, corp, freeb
 *
 * The DA/scope table is initially obtained for all scopes in the
 * useScopes list, then refreshed periodically when the
 * time stamp runs out. The time stamp is determined as the minimum
 * expiration time of the service URLs.
 *
 * @author James Kempf
 */

class SunDATable extends DATable {

    // The scopes identifier.

    final static String SCOPES_ID = "424242SUN-TABLE-SCOPES424242";

    // DA version number.

    final static String VERSION_ID = "424242SUN-TABLE-VERSION424242";

    // The scopes which reside on the SA only.

    private Vector saOnlyScopes = new Vector();

    // The cached vector of DA equivalence classes.

    private Vector cache = null;

    // The time when the cache should be refreshed.

    private long timeStamp = -1;

    /**
     * Construct a DATable. We get a cached table of accessable
     * DAs and scopes and the SA scope names to use for querying.
     */

    SunDATable() throws ServiceLocationException {

	// Remove the common scopes from the SA scopes. This will leave
	//  the private, SA only scopes.

	saOnlyScopes = conf.getSAOnlyScopes();

	Assert.slpassert(saOnlyScopes.size() > 0,
		      "no_sa_scopes",
		      new Object[0]);

	// Initialize the cache. We want the scopes that can be dynamically
	//  discovered. If we have been configured with scopes, then
	//  it will be those. If not, then we want whatever we can discovery.
	//  we only want the default version for client side.

	cache = getWireTable(conf.getConfiguredScopes(), Defaults.version);

    }

    /**
     * Return a hashtable of DA equivalence classes and multicast
     * scopes. Multicast scopes are stored in the special hashtable
     * key MULTICAST_KEY. Unicast DA equivalence classes are stored
     * under the key UNICAST_KEY.
     *
     * @param scopes Scope list for DAs needed.
     * @return Hashtable with DA addresses as keys and scopes to contact
     *         them with as values. Any scopes not associated with a
     *         DA come back stored under the key MULTICAST_KEY.
     *         Unicast DA equivalence classes are stored
     * 	     under the key UNICAST_KEY.
     */

    synchronized Hashtable findDAScopes(Vector scopes)
	throws ServiceLocationException {

	Hashtable ret = new Hashtable();

	Vector equivClasses = null;

	// Refresh the local cache if necessary.

	if (timeStamp <= System.currentTimeMillis()) {
	    Vector useScopes = conf.getConfiguredScopes();

	    cache = getWireTable(useScopes, Defaults.version);

	}

	equivClasses = (Vector)cache.clone();
	int i;

	// Sort through the local cache, matching against the input parameter.
	//  Collect multicast scopes.

	Vector multicastScopes = (Vector)scopes.clone();

	for (i = 0; i < equivClasses.size(); i++) {
	    DARecord rec = (DARecord)equivClasses.elementAt(i);
	    Vector daScopes = (Vector)rec.scopes.clone();

	    // Filter multicast scopes first. Remove any from the multicast
	    //  scope list that are in daScopes.

	    filterScopes(multicastScopes, daScopes, true);

	    // Now filter daScopes. Remove any from the daScopes that are
	    // not in the input scopes.

	    filterScopes(daScopes, scopes, false);

	    // Remove this record if there are none left.

	    if (daScopes.size() <= 0) {
		/*
		 *  Must decrement the index 'i' otherwise the next iteration
		 *  around the loop will miss the element immediately after
		 *  the element removed.
		 *
		 *  WARNING: Do not use 'i' again until the loop has
		 *           iterated as it may, after decrementing,
		 *           be negative.
		 */
		equivClasses.removeElementAt(i);
		i--;
		continue;
	    }
	}

	// Install the unicast and multicast scopes if any.

	if (multicastScopes.size() > 0) {
	    ret.put(MULTICAST_KEY, multicastScopes);

	}

	if (equivClasses.size() > 0) {
	    ret.put(UNICAST_KEY, equivClasses);

	}

	return ret;

    }

    /**
     * Remove a DA by address. We only remove it from the wire table
     * so if it's down temporarily, we'll get it back again.
     *
     * @param address The host address of the DA.
     * @param scopes The scopes.
     * @return True if removed, false if not.
     */

    boolean removeDA(InetAddress address, Vector scopes) {

	// Sort through the table of equivalence classes in cache.

	boolean foundit = false;
	int i;

	for (i = 0; i < cache.size(); i++) {
	    DARecord rec = (DARecord)cache.elementAt(i);
	    Vector daAddresses = rec.daAddresses;

	    // Ignore scopes, delete if there. Scopes will always be the
	    //  ones for which this DA is to be removed.

	    int j, m = daAddresses.size();

	    for (j = 0; j < m; j++) {
		InetAddress daaddr = (InetAddress)daAddresses.elementAt(j);

		// If they are equal, remove it, exit loop.

		if (address.equals(daaddr)) {
		    foundit = true;
		    daAddresses.removeElementAt(j);

		    // If the cache entry is empty, remove it.

		    if (daAddresses.size() <= 0) {
			cache.removeElementAt(i);

		    }

		    break;

		}
	    }
	}

	return foundit;

    }

    // Return a vector of DARecord equivalence classes by going out to the
    //  wire for them. Merge any that are in the current process'
    //  DAAddresses property.

    private Vector getWireTable(Vector scopes, int version)
	throws ServiceLocationException {

	Vector ret = new Vector();

	// Get replies from the SA server. These will be CSrvMsg replies.

	CSrvMsg msg = getSrvReply(scopes, version);

	// Process reply into the vector of equivalence classes by adding to
	// to those from the preconfigured DAs.

	processReply(msg, ret);

	// Return vector.

	return ret;
    }

    private CSrvMsg getSrvReply(Vector scopes, int version)
	throws ServiceLocationException {

	// Form the query.

	StringBuffer buf = new StringBuffer();
	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    buf.append("(");
	    buf.append(SCOPES_ID);
	    buf.append("=");
	    buf.append((String)scopes.elementAt(i));
	    buf.append(")");
	}

	// Add logical disjunction if there is more than one scope.

	if (i > 1) {
	    buf.insert(0, "(|");
	    buf.append(")");

	}

	// Add version number restriction.

	if (i > 0) {
	    buf.insert(0, "(&");

	}

	buf.append("(");
	buf.append(VERSION_ID);
	buf.append("=");
	buf.append((Integer.valueOf(version)).toString());
	buf.append(")");

	// Add closing paren if there were any scopes.

	if (i > 0) {
	    buf.append(")");

	}

	// Create the message object. Note that if scope vector is
	//  empty, the query is the null string, and so all DAs
	//  will be returned.

	CSrvMsg msg = new CSrvMsg(Defaults.locale,
				  Defaults.SUN_DA_SERVICE_TYPE,
				  saOnlyScopes,
				  buf.toString());

	// Send it down the pipe to the IPC process. It's a bad bug
	//  if the reply comes back as not a CSrvMsg.

	SrvLocMsg rply =
	    Transact.transactTCPMsg(conf.getLoopback(), msg, true);

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

	return (CSrvMsg)rply;
    }

    // Process CSrvMsg reply into DA equivalence class vector

    private void processReply(CSrvMsg msg, Vector ret)
	throws ServiceLocationException {

	int shortTimer = Integer.MAX_VALUE;

	// Get the URLs.

	Vector serviceURLs = msg.serviceURLs;

	// Process each service URL.

	int i, n = serviceURLs.size();

	for (i = 0; i < n; i++) {
	    ServiceURL url = (ServiceURL)serviceURLs.elementAt(i);

	    // If the time to live is less than the current minimum,
	    //  save it.

	    int lifetime = url.getLifetime();

	    if (lifetime < shortTimer) {
		shortTimer = lifetime;

	    }

	    // Get the host name and URL part.

	    String daaddr = url.getHost();
	    String urlpart = url.getURLPath();

	    // Parse URL part into scope list. Be
	    //  sure not to include the initial `/' in the parse.

	    StringTokenizer tk =
		new StringTokenizer(urlpart.substring(1,
						      urlpart.length()),
				    ";");
	    Vector daScopes = null;

	    while (tk.hasMoreElements()) {
		String attrExp = tk.nextToken();

		// Convert to an SLP attribute.

		ServiceLocationAttribute attr =
		    new ServiceLocationAttribute("(" + attrExp + ")", false);

		// Depending on the attribute id, do something.

		String id = attr.getId();
		Vector vals = attr.getValues();

		if (id.equals(SCOPES_ID)) {
		    daScopes = vals;

		} else {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"loopback_parse_error",
				new Object[] {url});
		}
	    }

	    // Add it to the equivalence class.

	    addToEquivClass(daaddr, daScopes, ret);

	}

	// Reset the timestamp.

	timeStamp = System.currentTimeMillis() + (long)(shortTimer * 1000);

    }

}
