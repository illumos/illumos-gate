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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.pntadm;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.bridge.BridgeException;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * Abstract class implemented by all the pntadm "function" classes.
 */
public abstract class PntAdmFunction
    extends DhcpCliFunction {

    /**
     * Short date format for printing/parsing lease expiration
     */
    DateFormat shortFormat = new SimpleDateFormat("MM/dd/yyyy");

    /**
     * Verbose date format for printing/parsing lease expiration.
     */
    DateFormat verboseFormat =
	DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.LONG);

    /**
     * The network on which the functions should "operate"
     */
    String networkName = null;

    /**
     * Sets the networkName.
     * @param network name of the network
     */
    public void setNetworkName(String network) {

	networkName = network;

    } // setNetworkName

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     */
    public String getString(String key) {

	return ResourceStrings.getString(key);

    } // getString

    /**
     * Returns whether or not hosts table is manageable.
     * @return whether or not hosts table is manageable.
     */
    public boolean isHostsManaged() {

	boolean result = false;

	try {
	    DhcpdOptions opts =
		getSvcMgr().readDefaults();
	    if (opts.getHostsResource() != null) {
		result = true;
	    } else {
		throw new BridgeException();
	    }
	} catch (BridgeException e) {
	    printErrMessage(getString("no_host_resource_warning"));
	}

	return result;

    } // isHostsManaged

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public void printErrMessage(String msg) {
	StringBuffer fullmsg = new StringBuffer(PntAdm.SIGNATURE);
	fullmsg.append(msg);
	DhcpCliPrint.printErrMessage(fullmsg.toString());
    } // printErrMessage

} // PntAdmFunction
