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

//  DATable.java:     Interface for DATables.
//  Author:           James Kempf
//  Created On:       Mon May 11 13:46:02 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Feb 22 15:47:37 1999
//  Update Count:     53
//


package com.sun.slp;

/**
 * DATable is an abstract class that provides the interface for DA
 * and scope discovery. A variety of implementations are possible.
 * The getDATable() method creates the right one from a subclass.
 *
 * @author James Kempf
 */

import java.util.*;
import java.net.*;

abstract class DATable extends Object {

    protected static DATable daTable;
    protected static SLPConfig conf;

    // System property naming the DATable implementation class to use.

    final static String DA_TABLE_CLASS_PROP = "sun.net.slp.DATableClass";

    // SA only scopes property.

    final static String SA_ONLY_SCOPES_PROP = "sun.net.slp.SAOnlyScopes";

    // Hashtable key for multicast scopes.

    final static String MULTICAST_KEY = "&&**^^MULTICASTxxxKEY^^**&&";

    // Hashtable key for DA equivalence classes.

    final static String UNICAST_KEY = "&&**^^UNICASTxxxKEY^^**&&";

    /**
     * A record for all DAs supporting exactly the same set of scopes.
     *
     * @author James Kempf
     */


    public static class DARecord extends Object {

	// The scopes supported.

	Vector scopes = null;		// String scope names

	Vector daAddresses = new Vector();  // InetAddress DA addresses

    }

    /**
     * Return a hashtable containing two entries:
     *
     * MULTICAST_KEY - Vector of scopes from the incoming vector that are not
     * supported by any known DA.
     *
     * UNICAST_KEY - Vector of DATable.DARecord objects containing
     * equivalence classes of DAs that all support the same set of scopes.
     * Only DAs supporting one or more scopes in the incoming vector
     * are returned.
     *
     * Note that the equivalence classes don't necessarily mean that the
     * set of scopes are mutually exclusive. For example, if DA1 supports
     * scopes A, B, and C; and DA2 supports scopes C and D, then they
     * are in separate equivalence classes even though they both support
     * C. But if DA2 supports A, B, and C; then it is in the same equivalence
     * class.
     *
     * @param scopes The scopes for which DAs are required.
     * @return A Hashtable with the multicast scopes and DAAddresses.
     */

    abstract Hashtable findDAScopes(Vector scopes)
	throws ServiceLocationException;

    /**
     * Remove a DA by address.
     *
     * @param address The host address of the DA.
     * @param scopes The scopes.
     * @return True if removed, false if not.
     */

    abstract boolean removeDA(InetAddress address, Vector scopes);

    /**
     * Return a vector of scopes that the SA or UA client should use.
     * Note that if no DAs are around, SA adverts must be used to
     * find SAs. We must sort through the returned DAs and apply
     * the scope prioritization algorithm to them.
     *
     * @return Vector of scopes for the SA or UA client to use.
     */

    synchronized Vector findScopes() throws ServiceLocationException {

	// First, get the DA addresses v.s. scopes table from the DAtable.
	//  This will also include DA addresses from the configuration file,
	//  if any. We don't filter on any scopes, since we want all of
	//  them. We are only interested in v2 scopes here.

	Vector scopes = new Vector();
	Hashtable daRec = daTable.findDAScopes(scopes);
	Vector daEquivClasses = (Vector)daRec.get(UNICAST_KEY);

	if (daEquivClasses != null) {

	    // Go through the equivalence classes and pull out scopes.

	    int i, n = daEquivClasses.size();

	    for (i = 0; i < n; i++) {
		DARecord rec = (DARecord)daEquivClasses.elementAt(i);
		Vector v = rec.scopes;

		int j, m = v.size();

		for (j = 0; j < m; j++) {
		    Object s = v.elementAt(j);

		    // Unicast scopes take precedence over multicast scopes,
		    //  so insert them at the beginning of the vector.

		    if (!scopes.contains(s)) {
			scopes.addElement(s);

		    }
		}
	    }
	}

	return scopes;
    }

    /**
     * Get the right DA table implementation. The property
     * sun.net.slp.DATableClass determines the class.
     *
     * @return The DATable object for this process' SLP requests.
     */


    static DATable getDATable() {

	// Return it right up front if we have it.

	if (daTable != null) {
	    return daTable;

	}

	conf = SLPConfig.getSLPConfig();

	// Link and instantiate it.

	daTable = linkAndInstantiateFromProp();

	return daTable;

    }

    // Link and instantiate the class in the property.

    static protected DATable linkAndInstantiateFromProp() {

	// Get the property.

	String className = System.getProperty(DA_TABLE_CLASS_PROP);

	if (className == null) {
	    Assert.slpassert(false,
			  "no_da_table",
			  new Object[] {DA_TABLE_CLASS_PROP});
	}

	Class tclass = null;

	// Link the class and instantiate the object.

	try {

	    tclass = Class.forName(className);
	    daTable = (DATable)tclass.newInstance();
	    return daTable;

	} catch (ClassNotFoundException ex) {

	    Assert.slpassert(false,
			  "no_da_table_class",
			  new Object[] {className});

	} catch (InstantiationException ex) {

	    Assert.slpassert(false,
			  "instantiation_exception",
			  new Object[] {className});

	} catch (IllegalAccessException ex) {

	    Assert.slpassert(false,
			  "access_exception",
			  new Object[] {className});

	}

	// We won't reach this point, since the assertions will capture
	//  any errors and kill the program.

	return null;
    }

    //
    // Utility functions for DA filtering and handling scopes.
    //

    // Filter scopes, removing any not on the filter list if inVector is
    //  false and removing any in the filter list if inVector is true.

    public static void
	filterScopes(Vector scopes, Vector filter, boolean inVector) {

	int i = 0;

	// Null or empty filter vector means that all should be accepted.

	if (filter != null && !(filter.size() <= 0)) {

	    while (i < scopes.size()) {
		String scope = (String)scopes.elementAt(i);

		if ((!inVector && !filter.contains(scope)) ||
		    (inVector && filter.contains(scope))) {
		    scopes.removeElementAt(i);

		} else {
		    i++;

		}
	    }
	}
    }

    // Add a new address to the equivalence class.

    static boolean addToEquivClass(String daaddr, Vector scopes, Vector ret) {

	// Create the InetAddress object.

	InetAddress addr = null;

	try {

	    addr = InetAddress.getByName(daaddr);

	} catch (UnknownHostException ex) {

	    if (conf.traceAll()) {
		conf.writeLog("unknown_da_address",
			      new Object[] {daaddr});

	    }

	    return false;
	}

	// Go through the existing vector.

	int i, n = ret.size();
	boolean equivalent = false;
	DARecord rec = null;

    outer: for (i = 0; i < n && equivalent == false; i++) {
	rec = (DARecord)ret.elementAt(i);
	Vector dascopes = rec.scopes;

	int j, m = dascopes.size();

	for (j = 0; j < m; j++) {
	    String scope = (String)dascopes.elementAt(j);

	    if (!scopes.contains(scope)) {
		continue outer;

	    }
	}

	equivalent = true;
    }

	// Make a new record if not equivalent.

	if (!equivalent) {
	    rec = new DATable.DARecord();
	    rec.scopes = (Vector)scopes.clone();

	    ret.addElement(rec);

	}


	// Add to record. Optimize, by putting the local address at the
	//  beginning of the vector.

	Vector interfaces = conf.getInterfaces();

	if (interfaces.contains(addr)) {
	    rec.daAddresses.insertElementAt(addr, 0);

	} else {
	    rec.daAddresses.addElement(addr);

	}

	return true;
    }

    /**
     * Validate the scope names. We check that they are all strings,
     * that none are the empty string. In addition, we collate to
     * remove duplicates, and lower case.
     */

    static void validateScopes(Vector scopes, Locale locale)
	throws ServiceLocationException {

	// Check for empty vector.

	if (scopes == null || scopes.size() <= 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"no_scope_vector",
				new Object[0]);
	}

	// Check for all strings and none empty.

	int i;
	Hashtable ht = new Hashtable();

	for (i = 0; i < scopes.size(); i++) {
	    Object o = scopes.elementAt(i);

	    if (!(o instanceof String)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"non_string_element",
				new Object[] {scopes});
	    }

	    String str = (String)o;

	    if (str.length() <= 0) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"null_element",
				new Object[] {scopes});
	    }

	    // Lower case, trim.

	    str = str.toLowerCase(locale).trim();

	    // Squeeze out spaces.

	    StringBuffer buf = new StringBuffer();
	    StringTokenizer tk =
		new StringTokenizer(str, ServiceLocationAttribute.WHITESPACE);
	    String tok = null;

	    while (tk.hasMoreTokens()) {

		// Add a single embedded whitespace for each group found.

		if (tok != null) {
		    buf.append(" ");

		}

		tok = tk.nextToken();
		buf.append(tok);
	    }

	    str = buf.toString();

	    // If it wasn't already seen, put it into the hashtable.

	    if (ht.get(str) == null) {
		ht.put(str, str);
		scopes.setElementAt(str, i);

	    } else {
		/*
		 *  Must decrement the index 'i' otherwise the next iteration
		 *  around the loop will miss the element immediately after
		 *  the element removed.
		 *
		 *  WARNING: Do not use 'i' again until the loop has
		 *           iterated as it may, after decrementing,
		 *           be negative.
		 */
		scopes.removeElementAt(i);
		i--;
		continue;
	    }
	}
    }

}
