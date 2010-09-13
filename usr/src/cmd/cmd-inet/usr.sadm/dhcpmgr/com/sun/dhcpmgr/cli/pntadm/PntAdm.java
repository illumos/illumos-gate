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
package com.sun.dhcpmgr.cli.pntadm;

import com.sun.dhcpmgr.cli.common.*;

import java.lang.IllegalArgumentException;

/**
 * This class represents the entry point to the DHCP CLI network tables
 * administration.
 */
public class PntAdm
    extends DhcpCliProgram {

    /**
     * The program signature.
     */
    public static final String SIGNATURE = "pntadm: ";

    /**
     * The valid options for all PntAdm administration.
     */
    private static String optString = "LPCRyavxA:D:M:r:p:u:s:i:f:e:m:c:n:B;";

    public static final int ADD_CLIENT_ENTRY		= 'A';
    public static final int MODIFY_CLIENT_ENTRY		= 'M';
    public static final int DELETE_CLIENT_ENTRY		= 'D';
    public static final int CREATE_NETWORK_TABLE	= 'C';
    public static final int REMOVE_NETWORK_TABLE	= 'R';
    public static final int DISPLAY_NETWORK_TABLE	= 'P';
    public static final int LIST_NETWORK_TABLES		= 'L';
    public static final int BATCH_EXECUTION		= 'B';

    public static final int VERIFY_MACRO	= 'y';
    public static final int CONVERT_CLIENTID	= 'a';
    public static final int RAW			= 'x';
    public static final int VERBOSE		= 'v';
    public static final int RESOURCE		= 'r';
    public static final int RESOURCE_CONFIG	= 'u';
    public static final int PATH		= 'p';
    public static final int SERVER		= 's';
    public static final int CLIENTID		= 'i';
    public static final int FLAGS		= 'f';
    public static final int LEASE_EXPIRATION	= 'e';
    public static final int MACRO_NAME		= 'm';
    public static final int COMMENT		= 'c';
    public static final int NEW_IP		= 'n';

    /**
     * Constructs a pntadm command.
     * @param args the options to the command.
     */
    public PntAdm(String [] args) {
	reset(args);
    } // constructor

    /**
     * Resets a PntAdm for reuse. Used by DhcpBatch program.
     * @param args the options to the command.
     */
    public void reset(String [] args) {

	clearFunction();
	options = new DhcpCliOptions();
	this.args = args;

    }

    /**
     * Returns the manpage signature for the program.
     * @return the manpage signature for the program.
     */
    public String getManPage() {
	return "pntadm(1M)";
    }

    /**
     * Displays program usage.
     */
    public void usage() {

	DhcpCliPrint.printErrMessage(getString("usage"));

    } // usage

    /**
     * Executes the program function.
     * @return SUCCESS, EXISTS, ENOENT, WARNING, or CRITICAL
     */
    public int execute() {

	int returnCode = SUCCESS;

	// Get the options and go exec the correct function.
	//
	GetOpt getopt = new GetOpt(args, optString);
	try {
	    int option;
	    while ((option = getopt.getNextOption()) != -1) {
		processArg(option, getopt.getOptionArg());
	    }

	    int networkIndex = getopt.getNextOptionIndex();
	    String network = null;

	    if (args.length == (networkIndex + 1)) {
		network = args[networkIndex];
	    } else if (args.length >= networkIndex + 1) {
		throw new IllegalArgumentException(
		    ResourceStrings.getString("invalid_args"));
	    }

	    if (function == null) {
		String msg = getString("no_function_error");
		throw new IllegalArgumentException(msg);
	    }

	    // Check the validity of the data store version.
	    //
	    if (!function.isVersionValid(false)) {
		return (CRITICAL);
	    }

	    // Not all functions accept network arguments.
	    //
	    if (function instanceof ListNetworkTables ||
		function instanceof PntAdmBatch) {
		if (network != null) {
		    String msg = getString("network_specified");
		    throw new IllegalArgumentException(msg);
		}
	    } else {
		if (network == null) {
		    String msg = getString("no_network_specified");
		    throw new IllegalArgumentException(msg);
		}
	    }

	    // Create a DHCP datastore object with the user specified objects.
	    //
	    function.setDhcpDatastore(options.valueOf(RESOURCE),
		options.valueOf(PATH), options.valueOf(RESOURCE_CONFIG));

	    function.setOptions(options);
	    ((PntAdmFunction)function).setNetworkName(network);
	    returnCode = function.execute();

	} catch (IllegalArgumentException e) {
	    StringBuffer msg = new StringBuffer(SIGNATURE);
	    msg.append(DhcpCliFunction.getMessage(e));
	    DhcpCliPrint.printErrMessage(msg.toString());
	    DhcpCliPrint.printErrMessage("");
	    usage();
	    returnCode = CRITICAL;
	} catch (Throwable e) {
	    StringBuffer msg = new StringBuffer(SIGNATURE);
	    msg.append(DhcpCliFunction.getMessage(e));
	    DhcpCliPrint.printErrMessage(msg.toString());
	    returnCode = CRITICAL;
	}

	return (returnCode);

    } // execute

    /**
     * Processes one program argument.
     * @param option the option flag
     * @param value the option value(if any)
     * @exception IllegalArgumentException if an invalid argument was entered
     */
    public void processArg(int option, String value)
	throws IllegalArgumentException {

    	switch (option) {
	case ADD_CLIENT_ENTRY:
	    setFunction(new AddClientEntry(value));
	    break;
	case MODIFY_CLIENT_ENTRY:
	    setFunction(new ModifyClientEntry(value));
	    break;
	case DELETE_CLIENT_ENTRY:
	    setFunction(new DeleteClientEntry(value));
	    break;
	case CREATE_NETWORK_TABLE:
	    setFunction(new CreateNetworkTable());
	    break;
	case REMOVE_NETWORK_TABLE:
	    setFunction(new RemoveNetworkTable());
	    break;
	case DISPLAY_NETWORK_TABLE:
	    setFunction(new DisplayNetworkTable());
	    break;
	case LIST_NETWORK_TABLES:
	    setFunction(new ListNetworkTables());
	    break;
	case BATCH_EXECUTION:
	    setFunction(new PntAdmBatch(value));
	    break;
	default:
	    options.setOption(option, value);
	}

    } // processArg

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     * @return string from resource bundle.
     */
    public String getString(String key) {

	return ResourceStrings.getString(key);

    } // getString

    /**
     * The entry point for the program.
     * @param args the program arguments
     */
    public static void main(String[] args) {

	PntAdm pntadm = new PntAdm(args);
	int returnCode = PntAdm.CRITICAL;
	if (pntadm.isValidUser()) {
	    returnCode = pntadm.execute();
	}
	System.exit(returnCode);

    } // main

} // PntAdm
