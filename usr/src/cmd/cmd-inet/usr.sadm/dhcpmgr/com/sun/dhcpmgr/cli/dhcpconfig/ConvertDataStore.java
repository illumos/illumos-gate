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
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.data.DhcpDatastore;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.bridge.ExistsException;

public class ConvertDataStore extends DhcpCfgFunction {

    static final int supportedOptions[] = {
	DhcpCfg.FORCE,
	DhcpCfg.KEEP_TABLES,
	DhcpCfg.RESOURCE,
	DhcpCfg.RESOURCE_CONFIG,
	DhcpCfg.PATH
    };

    public ConvertDataStore() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.CONVERT_DATA_STORE);
    }

    public int execute() throws IllegalArgumentException {

	// User must define both resource and path.
	//
	if (options.valueOf(DhcpCfg.RESOURCE) == null ||
	    options.valueOf(DhcpCfg.PATH) == null) {
	    String msg = getString("convert_null_datastore_error");
	    throw new IllegalArgumentException(msg);
	}

	try {
	    setDhcpDatastore(getSvcMgr().getDataStore(
		options.valueOf(DhcpCfg.RESOURCE)));
	    getDhcpDatastore().setLocation(options.valueOf(DhcpCfg.PATH));
	    getDhcpDatastore().setConfig(
		options.valueOf(DhcpCfg.RESOURCE_CONFIG));
	} catch (Throwable e) {
	    // resource will not be valid
	}


	if (getDhcpDatastore() == null || !getDhcpDatastore().isEnabled()) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getDhcpDatastore().getResource();
	    printErrMessage(getString("convert_invalid_resource_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Should we delete the dhcptab and the network tables after
	// they have been converted?
	//
	boolean deleteTables = !options.isSet(DhcpCfg.KEEP_TABLES);

	// Get the old configuration values.
	//
	DhcpdOptions dhcpdOptions = null;
	try {
	    dhcpdOptions = getSvcMgr().readDefaults();
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("convert_conf_read_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	// If the source, destination, and version are all the same
	// then there is nothing to do ... report it as an error.
	//
	DhcpDatastore oldDatastore = dhcpdOptions.getDhcpDatastore();
	if (getDhcpDatastore().equals(oldDatastore)) {
	    printErrMessage(getString("convert_same_datastore_error"));
	    return (DhcpCfg.FAILURE);
	}

	// Confirm?
	//
	if (!options.isSet(DhcpCfg.FORCE)) {
	    printMessage(getString("convert_explanation"));
	    String confirmationMsg = getString("convert_confirmation");
	    String affirmative = getString("affirmative");
	    String negative = getString("negative");
	    boolean doit = Console.promptUser(confirmationMsg, affirmative,
		negative, true);
	    if (!doit) {
		return (DhcpCfg.FAILURE);
	    }
	}

	// Create the location if it does not exist.
	//
	try {
	    getSvcMgr().makeLocation(getDhcpDatastore());
	} catch (ExistsException e) {
	    // this is o.k.
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getDhcpDatastore().getLocation();
	    printErrMessage(getString("convert_make_location_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Shut down the server if it is running
	//
	try {
	    if (getSvcMgr().isServerRunning()) {
		getSvcMgr().shutdown();
		printMessage(getString("convert_shutdown_progress"));
	    } else {
		printMessage(getString("convert_no_shutdown_progress"));
	    }
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("convert_shutdown_error"), arguments);
	}

	// Convert the dhcptab.
	//
	try {
	    getDhcptabMgr().cvtDhcptab(getDhcpDatastore());
	    printMessage(getString("convert_dhcptab_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("convert_dhcptab_error"), arguments);
	    deleteTables = false;
	}

	// Go get a list of the network tables to convert.
	//
	Network[] networks = new Network[0];
	try {
	    networks = getNetMgr().getNetworks(oldDatastore);
	    if (networks == null) {
		networks = new Network[0];
	    }
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("convert_get_nets_error"), arguments);
	    deleteTables = false;
	}

	// Convert the network tables
	//
	for (int i = 0; i < networks.length; ++i) {
	    String netString = networks[i].toString();
	    try {
		getNetMgr().cvtNetwork(netString, getDhcpDatastore());
		Object [] arguments = new Object[1];
		arguments[0] = netString;
		printMessage(getString("convert_network_progress"), arguments);
	    } catch (Throwable e) {
		Object [] arguments = new Object[2];
		arguments[0] = netString;
		arguments[1] = getMessage(e);
		printErrMessage(getString("convert_network_error"),
		    arguments);
	    }
	}

	dhcpdOptions.setDhcpDatastore(getDhcpDatastore());
	try {
	    getSvcMgr().writeDefaults(dhcpdOptions);
	    printMessage(getString("convert_conf_update_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("convert_conf_write_error"), arguments);
	    deleteTables = false;
	}

	if (deleteTables) {
	    // Delete the network tables
	    //
	    for (int i = 0; i < networks.length; ++i) {
		String netString = networks[i].toString();
		try {
		    getNetMgr().deleteNetwork(netString, false, oldDatastore);
		    Object [] arguments = new Object[1];
		    arguments[0] = netString;
		    printMessage(getString("convert_delete_network_progress"),
			arguments);
		} catch (Throwable e) {
		    Object [] arguments = new Object[2];
		    arguments[0] = netString;
		    arguments[1] = getMessage(e);
		    printErrMessage(getString("convert_delete_network_error"),
			arguments);
		}
	    }

	    // Delete the dhcptab
	    //
	    try {
		getDhcptabMgr().deleteDhcptab(oldDatastore);
		printMessage(getString("convert_delete_dhcptab_progress"));
	    } catch (Throwable e) {
		Object [] arguments = new Object[1];
		arguments[0] = getMessage(e);
		printErrMessage(getString("convert_delete_dhcptab_error"),
		    arguments);
	    }
	}

	// Start it up.
	//
	if (dhcpdOptions.isDaemonEnabled()) {
	    try {
		getSvcMgr().startup();
		printMessage(getString("convert_startup_progress"));
	    } catch (Throwable e) {
		Object [] arguments = new Object[1];
		arguments[0] = getMessage(e);
		printErrMessage(getString("convert_startup_error"), arguments);
	    }
	}

	return (DhcpCfg.SUCCESS);

    } // execute

} // ConvertDataStore
