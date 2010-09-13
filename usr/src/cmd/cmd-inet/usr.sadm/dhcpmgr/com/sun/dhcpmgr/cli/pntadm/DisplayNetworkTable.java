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

import com.sun.dhcpmgr.cli.common.Format;
import com.sun.dhcpmgr.data.DhcpClientRecord;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.bridge.NoEntryException;
import com.sun.dhcpmgr.bridge.NoTableException;

import java.util.Date;
import java.lang.IllegalArgumentException;

/**
 * The main class for the "display network table" functionality
 * of pntadm.
 */
public class DisplayNetworkTable extends PntAdmFunction {

    /**
     * The valid options associated with displaying a network table.
     */
    static final int supportedOptions[] = {
	PntAdm.VERBOSE,
	PntAdm.RAW,
	PntAdm.RESOURCE,
	PntAdm.RESOURCE_CONFIG,
	PntAdm.PATH
    };

    /**
     * Constructs a DisplayNetworkTable object.
     */
    public DisplayNetworkTable() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (PntAdm.DISPLAY_NETWORK_TABLE);
    }

    /**
     * Executes the "display network table" functionality.
     * @return PntAdm.SUCCESS, PntAdm.ENOENT, PntAdm.WARNING, or
     * PntAdm.CRITICAL
     */
    public int execute()
	throws IllegalArgumentException {

	int returnCode = PntAdm.SUCCESS;

	// Is this a verbose display?
	//
	boolean verbose = false;
	if (options.isSet(PntAdm.VERBOSE)) {
	    verbose = true;
	}

	// Is this a raw display?
	//
	boolean raw = false;
	if (options.isSet(PntAdm.RAW)) {
	    raw = true;
	}

	if (verbose && raw) {
	    String msg = getString("display_mode_error");
	    throw new IllegalArgumentException(msg);
	}

	// Display the network table.
	DhcpClientRecord [] dhcpClientRecords = null;
	try {

	    Network network = getNetMgr().getNetwork(networkName);
	    if (network == null) {
		printErrMessage(getString("network_name_error"));
		return (PntAdm.WARNING);
	    }

	    dhcpClientRecords =
		getNetMgr().loadNetwork(network.toString(),
		    getDhcpDatastore());
	} catch (NoTableException e) {
	    printErrMessage(getMessage(e));
	    return (PntAdm.ENOENT);
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    return (PntAdm.WARNING);
	}

	Format.print(System.out, "%-8s\t", getString("Client_ID"));
	Format.print(System.out, "%-4s\t", getString("Flags"));
	Format.print(System.out, "%-8s\t", getString("Client_IP"));
	Format.print(System.out, "%-8s\t", getString("Server_IP"));
	Format.print(System.out, "%-25s\t", getString("Lease_Expiration"));
	Format.print(System.out, "%-8s\t", getString("Macro"));
	Format.print(System.out, "%s\n\n", getString("Comment"));

	DhcpClientRecord dhcpClientRecord;
	for (int i = 0; 
	    dhcpClientRecords != null && i < dhcpClientRecords.length;
	    i++) {

	    dhcpClientRecord = dhcpClientRecords[i];
	    Format.print(System.out, "%-8s\t", dhcpClientRecord.getClientId());
	    Format.print(System.out, "%-4s\t",
		dhcpClientRecord.getFlagString(verbose));

	    String client;
	    if (verbose) {
		client = dhcpClientRecord.getClientIP().getHostName();
	    } else {
		client = dhcpClientRecord.getClientIP().toString();
	    }
	    Format.print(System.out, "%-8s\t", client);

	    String server;
	    if (verbose) {
		server = dhcpClientRecord.getServerIP().getHostName();
	    } else {
		server = dhcpClientRecord.getServerIP().toString();
	    }
	    Format.print(System.out, "%-8s\t", server);

	    String lease;
	    Date expiration = dhcpClientRecord.getExpiration();
	    if (raw) {
		// Print date in seconds since the epoch
		lease = Long.toString(expiration.getTime()/1000);
	    } else if (expiration == null || expiration.getTime() == 0) {
		lease = getString("Zero");
	    } else if (expiration.getTime() < 0) {
		lease = getString("Forever");
	    } else if (verbose) {
		// Print date and time for lease in locale format
		lease = verboseFormat.format(expiration);
	    } else {
		// Print just the lease date in short format for locale
		lease = shortFormat.format(expiration);
	    }
	    Format.print(System.out, "%-25s\t", lease);

	    Format.print(System.out, "%-8s\t", dhcpClientRecord.getMacro());
	    Format.print(System.out, "%s\n", dhcpClientRecord.getComment());
	}

	return (returnCode);

    } // execute

} // DisplayNetworkTable
