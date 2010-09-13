/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.data.IPAddress;
import com.sun.dhcpmgr.data.ValidationException;

import java.util.Vector;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.text.MessageFormat;

/**
 * Class that builds a vector of IPAddress objects.
 */
public class IPAddressList extends Vector {

    /**
     * Construct a IPAddressList from a String list of IP addresses
     * and/or host names.
     * @param addresses a String list of IP addresses
     */
    public IPAddressList(String addresses) throws ValidationException {

	removeAllElements();

	if (addresses == null) {
	    return;
	}

	StringTokenizer st = new StringTokenizer(addresses, ",");
	while (st.hasMoreTokens()) {
	    String address = st.nextToken();
	    try {
		addElement(new IPAddress(address.trim()));
	    } catch (ValidationException e) {
		Object [] args = new Object[1];
		args[0] = address;
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_ip_address"));
		throw new ValidationException(form.format(args));
	    }
	}
    } // constructor

    /**
     * Construct a IPAddressList from an array of IPAddress objects.
     * @param addresses array of IPAddress objects
     */
    public IPAddressList(IPAddress [] addresses) {

	removeAllElements();

	if (addresses == null) {
	    return;
	}

	for (int i = 0; i < addresses.length; i++) {
	    addElement(addresses[i]);
	}
    } // constructor

    /**
     * Returns an array of IP Addresses.
     * @return an array of IP Addresses.
     */
    public IPAddress [] toIPAddressArray() {
	return ((IPAddress [])toArray(new IPAddress[size()]));
    } // toIPAddressArray

    /**
     * Returns a comma separated list of IP Addresses.
     * @return a comma separated list of IP Addresses.
     */
    public String toString() {
	StringBuffer b = new StringBuffer();
	Enumeration en = elements();
	while (en.hasMoreElements()) {
	    if (b.length() != 0) {
		b.append(',');
	    }
	    b.append(((IPAddress)en.nextElement()).getHostAddress());
	}
	return b.toString();
    } // toString

} // IPAddressList
