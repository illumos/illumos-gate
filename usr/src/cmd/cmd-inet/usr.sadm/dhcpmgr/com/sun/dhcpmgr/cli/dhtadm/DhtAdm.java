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
package com.sun.dhcpmgr.cli.dhtadm;

import com.sun.dhcpmgr.cli.common.*;
import com.sun.dhcpmgr.server.*;

import java.lang.IllegalArgumentException;
import java.text.MessageFormat;

/**
 * This class represents the entry point to the DHCP CLI dhcptab
 * administration.
 */
public class DhtAdm
    extends DhcpCliProgram {

    /**
     * The program signature.
     */
    public static final String SIGNATURE = "dhtadm: ";

    /**
     * The valid options for all DhtAdm administration.
     */
    private static String optString = "ACDIMPRvgr:p:u:s:m:n:e:d:B;";

    public static final int ADD_ENTRY		= 'A';
    public static final int MODIFY_ENTRY	= 'M';
    public static final int DELETE_ENTRY	= 'D';
    public static final int CREATE_TABLE	= 'C';
    public static final int REMOVE_TABLE	= 'R';
    public static final int DISPLAY_TABLE	= 'P';
    public static final int BATCH_EXECUTION	= 'B';

    public static final int MACRONAME		= 'm';
    public static final int SYMBOLNAME		= 's';
    public static final int NEWNAME		= 'n';
    public static final int DEFINITION		= 'd';
    public static final int EDITSYMBOL		= 'e';
    public static final int RESOURCE		= 'r';
    public static final int RESOURCE_CONFIG	= 'u';
    public static final int PATH		= 'p';
    public static final int VERBOSE		= 'v';
    public static final int SIGHUP		= 'g';

    /**
     * Constructs a dhtadm command.
     * @param args the options to the command.
     */
    public DhtAdm(String [] args) {

	reset(args);
	// Set the options.
	//
	options = new DhcpCliOptions();
	this.args = args;

    } // constructor

    /**
     * Resets a DhtAdm for reuse. Used by DhcpBatch program.
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
	return "dhtadm(1M)";
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

	    int lastIndex = getopt.getNextOptionIndex();
	    if (args.length != lastIndex) {
		Object [] arguments = new Object[1];
		arguments[0] = args[lastIndex];
		MessageFormat form =
		    new MessageFormat(getString("invalid_arg"));
		throw new IllegalArgumentException(form.format(arguments));
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

	    // Create a DHCP datastore object with the user specified objects.
	    //
	    function.setDhcpDatastore(options.valueOf(RESOURCE),
		options.valueOf(PATH), options.valueOf(RESOURCE_CONFIG));

	    function.setOptions(options);
	    function.setStandardOptions();
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

	// Signal server if requested by user and main operation successful
	if (returnCode == SUCCESS && options.isSet(SIGHUP)) {
	    try {
		DhcpMgr dhcpMgr = new DhcpMgrImpl();
		dhcpMgr.getDhcpServiceMgr().reload();
	    } catch (Throwable e) {
		returnCode = WARNING;
		// Display warning
		StringBuffer msg = new StringBuffer(SIGNATURE);
		msg.append(getString("sighup_failed"));
		DhcpCliPrint.printErrMessage(msg.toString());
	    }
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

	    case ADD_ENTRY:
		setFunction(new AddEntry());
		break;
	    case MODIFY_ENTRY:
		setFunction(new ModifyEntry());
		break;
	    case DELETE_ENTRY:
		setFunction(new DeleteEntry());
		break;
	    case CREATE_TABLE:
		setFunction(new CreateTable());
		break;
	    case REMOVE_TABLE:
		setFunction(new RemoveTable());
		break;
	    case DISPLAY_TABLE:
		setFunction(new DisplayTable());
		break;
	    case BATCH_EXECUTION:
		setFunction(new DhtAdmBatch(value));
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

	DhtAdm dhtadm = new DhtAdm(args);
	int returnCode = DhtAdm.CRITICAL;
	if (dhtadm.isValidUser()) {
	    returnCode = dhtadm.execute();
	}
	System.exit(returnCode);

    } // main

} // DhtAdm
