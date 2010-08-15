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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.Console;
import com.sun.dhcpmgr.data.ValidationException;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.data.Macro;
import com.sun.dhcpmgr.data.DhcpdOptions;

/**
 * The main class for the "unconfigure DHCP server" functionality of
 * dhcpconfig.
 */
public class UnconfigureDhcp extends DhcpCfgFunction {

    /**
     * The valid options associated with unconfiguring a DHCP server.
     */
    static final int supportedOptions[] = {
	DhcpCfg.FORCE,
	DhcpCfg.DELETE_TABLES
    };

    /**
     * Constructs a UnconfigureDhcp object.
     */
    public UnconfigureDhcp() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.UNCONFIGURE_DHCP);
    }

    /**
     * Executes the "unconfigure DHCP server" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() {

	// Confirm?
	//
	if (!options.isSet(DhcpCfg.FORCE)) {
	    String confirmationMsg = getString("unconfigure_confirmation");
	    String affirmative = getString("affirmative");
	    String negative = getString("negative");
	    boolean doit = Console.promptUser(confirmationMsg, affirmative,
		negative, true);
	    if (!doit) {
		return (DhcpCfg.FAILURE);
	    }
	}

	// Retrieve the configuration values from the server.
	//
	boolean isRelay = false;
	try {
	    DhcpdOptions opts = getSvcMgr().readDefaults();
	    isRelay = opts.isRelay();
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("unconfigure_read_conf_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Shut down the server if it is running
	//
	try {
	    if (getSvcMgr().isServerRunning()) {
		getSvcMgr().shutdown();
		printMessage(getString("unconfigure_shutdown_progress"));
	    } else {
		printMessage(getString("unconfigure_no_shutdown_progress"));
	    }
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("unconfigure_shutdown_error"),
		arguments);
	}

	// Should we delete the dhcptab and the network tables?
	//
	boolean deleteTables = options.isSet(DhcpCfg.DELETE_TABLES);

	// If this server is just acting as a relay then we don't need to
	// clean up the dhcptab or the networks.
	//
	if (!isRelay) {
	    // Delete the server macro.
	    //
	    try {
		Macro serverMacro =
		    new Macro(getSvcMgr().getShortServerName());
		getDhcptabMgr().deleteRecord(serverMacro, false);
		printMessage(getString("unconfigure_server_macro_progress"));
	    } catch (Throwable e) {
		Object [] arguments = new Object[1];
		arguments[0] = getMessage(e);
		printErrMessage(getString("unconfigure_server_macro_error"),
		    arguments);
	    }

	    // Delete the dhcptab and the network tables if requested.
	    //
	    if (deleteTables) {
		// Go get a list of the network tables to delete.
		//
		Network[] networks = new Network[0];
		try {
		    networks = getNetMgr().getNetworks();
		    if (networks == null) {
			networks = new Network[0];
		    }
		} catch (Throwable e) {
		    Object [] arguments = new Object[1];
		    arguments[0] = getMessage(e);
		    printErrMessage(getString("unconfigure_get_nets_error"),
			arguments);
		}

		// Delete the network tables
		//
		for (int i = 0; i < networks.length; ++i) {
		    String netString = networks[i].toString();
		    try {
			getNetMgr().deleteNetwork(netString, false);
			Object [] arguments = new Object[1];
			arguments[0] = netString;
			printMessage(getString("unconfigure_network_progress"),
			    arguments);
		    } catch (Throwable e) {
			Object [] arguments = new Object[2];
			arguments[0] = netString;
			arguments[1] = getMessage(e);
			printErrMessage(getString("unconfigure_network_error"),
			    arguments);
		    }
		}

		// Delete the dhcptab
		//
		try {
		    getDhcptabMgr().deleteDhcptab();
		    printMessage(getString("unconfigure_dhcptab_progress"));
		} catch (Throwable e) {
		    Object [] arguments = new Object[1];
		    arguments[0] = getMessage(e);
		    printErrMessage(getString("unconfigure_dhcptab_error"),
			arguments);
		}
	    }
	}

	// Remove the configuration file
	//
	try {
	    getSvcMgr().removeDefaults();
	    printMessage(getString("unconfigure_remove_conf_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("unconfigure_remove_conf_error"),
		arguments);
	}

	return (DhcpCfg.SUCCESS);

    } // execute

} // UnconfigureDhcp
