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
package com.sun.dhcpmgr.cli.dhcpconfig;

import java.util.ArrayList;
import java.util.StringTokenizer;
import java.text.MessageFormat;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.ExistsException;

import com.sun.dhcpmgr.common.ExportController;
import com.sun.dhcpmgr.common.Exporter;

/**
 * The main class for the "export move data" functionality of dhcpconfig.
 */
public class ExportData extends DhcpCfgFunction implements Exporter {

    /**
     * The valid options associated with exporting data.
     */
    private static final int supportedOptions[] = {
	DhcpCfg.MACRO_LIST,
	DhcpCfg.OPTION_LIST,
	DhcpCfg.NETWORK_ADDRESSES,
	DhcpCfg.DELETE_DATA,
	DhcpCfg.FORCE,
	DhcpCfg.SIGHUP
    };

    /**
     * Keyword that may be used to define all options, all macros, or all
     * network tables.
     */
    private static final String ALL = "ALL";

    /**
     * The name of the export file.
     */
    private String exportFile;

    /**
     * Simple constructor
     */
    public ExportData(String exportFile) {

	validOptions = supportedOptions;
	this.exportFile = exportFile;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.EXPORT_DATA);
    }

    /**
     * Executes the "export move data" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() {

	// Make sure that server is configured as a DHCP server.
	//
	if (!isServerConfigured()) {
	    return (DhcpCfg.FAILURE);
	}

	// Check the validity of the data store version.
	if (!isVersionValid(false)) {
	    return (DhcpCfg.FAILURE);
	}

	// Should export file be overwritten if it exists?
	boolean force = options.isSet(DhcpCfg.FORCE);

	// Should exported data be deleted or just copied?
	boolean deleteData = options.isSet(DhcpCfg.DELETE_DATA);
	
	// Create the export controller
	ExportController controller = new ExportController(this, getDhcpMgr());
	controller.setFile(exportFile);
	// Store user name
	controller.setUser(System.getProperty("user.name"));

	/*
	 * Get the macro list. The keyword of "ALL" means that all macros in
	 * the dhcptab should be exported. 
	 */
	if (options.isSet(DhcpCfg.MACRO_LIST)) {
	    String macroNames = options.valueOf(DhcpCfg.MACRO_LIST);
	    if (ALL.equals(macroNames)) {
		controller.setAllMacros();
	    } else {
		// Parse macro list and give to controller
		controller.setMacros(argsToArray(macroNames));
	    }
	}

	/*
	 * Get the option list. Keyword of "ALL" means that all options in the
	 * dhcptab should be exported.
	 */
	if (options.isSet(DhcpCfg.OPTION_LIST)) {
	    String optionNames = options.valueOf(DhcpCfg.OPTION_LIST);
	    if (ALL.equals(optionNames)) {
		controller.setAllOptions();
	    } else {
		controller.setOptions(argsToArray(optionNames));
	    }
	}

	/*
	 * Get the list of network addresses. If the option is set to the
	 * keyword "ALL", all network tables should be exported.
	 */
	if (options.isSet(DhcpCfg.NETWORK_ADDRESSES)) {
	    String addrs = options.valueOf(DhcpCfg.NETWORK_ADDRESSES);
	    if (ALL.equals(addrs)) {
		controller.setAllNetworks();
	    } else {
		// Parse network list
		IPAddressList networkAddresses;
		try {
		    networkAddresses = new IPAddressList(addrs);
		} catch (ValidationException e) {
		    printErrMessage(getMessage(e));
		    printErrMessage(getString("export_abort"));
		    return (DhcpCfg.FAILURE);
		}

		// Now ensure all networks specified exist
		ArrayList netList = new ArrayList();
		try {
		    Network [] nets = getNetMgr().getNetworks();

		    for (int i = 0;
			    !networkAddresses.isEmpty() && i < nets.length;
			    ++i) {
			int index = networkAddresses.indexOf(
			    nets[i].getNetworkNumber());
			// Found; remove from search list, add to export list
			if (index != -1) {
			    netList.add(nets[i]);
			    networkAddresses.remove(index);
			}
		    }
		} catch (BridgeException e) {
		    e.printStackTrace();
		}

		if (!networkAddresses.isEmpty()) {
		    // One of the networks was not valid
		    System.err.print(networkAddresses.firstElement());
		    System.err.println(" is not a valid network");
		    return (DhcpCfg.FAILURE);
		}

		controller.setNetworks(
		    (Network [])netList.toArray(new Network[0]));
	    }
	}

	// Do the export
	try {
	    // result should affect exit status once that's implemented
	    if (!controller.exportData(deleteData, force)) {
		return (DhcpCfg.FAILURE);
	    }
	} catch (ExistsException e) {
	    // File already exists, print error and exit
	    Object [] arguments = new Object[1];
	    arguments[0] = exportFile;
	    printErrMessage(getString("export_file_exist_error"), arguments);
    	    printErrMessage(getString("export_abort"));
	    return (DhcpCfg.FAILURE);
	}

	// Signal server if requested by user
	try {
	    if (options.isSet(DhcpCfg.SIGHUP)) {
		getSvcMgr().reload();
	    }
	} catch (Throwable e) {
	    printErrMessage(getString("sighup_failed"));
	    return (DhcpCfg.FAILURE);
	}

	return (DhcpCfg.SUCCESS);

    } // execute

    /**
     * Convert a comma-separated list of arguments to an array of tokens
     */
    private String [] argsToArray(String arg) {
	ArrayList argList = new ArrayList();
	StringTokenizer st = new StringTokenizer(arg, ",");
	while (st.hasMoreTokens()) {
	    argList.add(st.nextToken());
	}
	return (String [])argList.toArray(new String[0]);
    }

    /**
     * Initialize progress.  A no-op for us.
     */
    public void initializeProgress(int length) {
	// Do nothing
    }

    /**
     * Display progress.  Just print the message.
     */
    public void updateProgress(int done, String message) {
	printMessage(message);
    }

    /**
     * Display an error.
     */
    public void displayError(String message) {
	Object [] arguments = new Object[1];
	arguments[0] = message;
	printErrMessage(getString("export_err_message"), arguments);
    }

    /**
     * Display a set of errors during export
     */
    public void displayErrors(String msg, String label, ActionError [] errs) {
	printErrMessage(msg);
	Object [] args = new Object[3];
	args[0] = label;
	MessageFormat form =
	    new MessageFormat(getString("export_action_error"));
	for (int i = 0; i < errs.length; ++i) {
	    args[1] = errs[i].getName();
	    args[2] = errs[i].getException().getMessage();
	    printErrMessage(form.format(args));
	}
    }

} // ExportData
