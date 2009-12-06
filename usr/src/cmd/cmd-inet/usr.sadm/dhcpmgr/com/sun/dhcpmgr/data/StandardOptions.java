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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.data;

import java.util.*;
import java.io.Serializable;

/**
 * This class defines the set of standard DHCP options we know about.
 */
public class StandardOptions implements Serializable {

    /*
     * The following list of options are the ones that we use
     * in order to configure DHCP for the user.
     */
    public static final String CD_SUBNETMASK = "Subnet";
    public static final String CD_TIMEOFFSET = "UTCoffst";
    public static final String CD_ROUTER = "Router";
    public static final String CD_TIMESERV = "Timeserv";
    public static final String CD_DNSSERV = "DNSserv";
    public static final String CD_DNSDOMAIN = "DNSdmain";
    public static final String CD_BROADCASTADDR = "Broadcst";
    public static final String CD_ROUTER_DISCVRY_ON = "RDiscvyF";
    public static final String CD_NIS_DOMAIN = "NISdmain";
    public static final String CD_NIS_SERV = "NISservs";
    public static final String CD_LEASE_TIME = "LeaseTim";
    public static final String CD_BOOL_LEASENEG = "LeaseNeg";

    /*
     * Following list of options must be kept in sync with the list in
     * usr/src/cmd/cmd-inet/usr.lib/in.dhcpd/dhcptab.c in SunOS source tree.
     */
    private static Option [] options = null;

    /**
     * Return the size of this list
     * @return the number of options known
     */
    public static int size() {
	return (options == null) ? 0 :options.length;
    }

    /**
     * Enumerate the options defined here.
     * @return an Enumeration of the standard options.
     */
    public Enumeration enumOptions() {
	return new Enumeration() {
	    int cursor = 0;

	    public boolean hasMoreElements() {
		return (cursor < size());
	    }

	    public Object nextElement() throws NoSuchElementException {
		if (cursor >= size()) {
		    throw new NoSuchElementException();
		}
		return (options[cursor++]);
	    }
	};
    }

    /**
     * Return all options as an array
     * @return the array of options defined here
     */
    public static Option [] getAllOptions() {
	return options;
    }

    /**
     * Set all options as an array
     * @param options array of STANDARD options
     */
    public static void setAllOptions(Option [] ops) {
	options = ops;
    }

    /**
     * Find the option name for a given code.  This could be
     * much faster but not clear that it needs to be yet.
     * @return the name of the option, or null if that code is unknown.
     */
    public static String nameForCode(int code) {
	for (int i = 0; i < options.length; ++i) {
	    if (options[i].getCode() == code) {
		return options[i].getKey();
	    }
	}
	return null;
    }
}
