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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.cli.common.*;

import java.lang.IllegalArgumentException;
import java.text.MessageFormat;

/**
 * This class represents the entry point to the DHCP CLI dhcp configuration
 * administration.
 */
public class DhcpCfg
    extends DhcpCliProgram {

    /**
     * The program signature.
     */
    public static final String SIGNATURE = "dhcpconfig: ";

    /**
     * The valid options for all DhcpCfg administration.
     */
    private static String optString =
	"DUCnfxbkgI:R:N:X:r;p:u:l:d;a:m:t:y:s:o:P;Seq";

    public static final int CONFIGURE_DHCP		= 'D';
    public static final int CONFIGURE_BOOTP		= 'R';
    public static final int UNCONFIGURE_DHCP		= 'U';
    public static final int CONFIGURE_NETWORK		= 'N';
    public static final int CONVERT_DATA_STORE		= 'C';
    public static final int EXPORT_DATA			= 'X';
    public static final int IMPORT_DATA			= 'I';
    public static final int CONFIGURE_SERVER_PARAMETER	= 'P';
    public static final int CONFIGURE_SERVICE		= 'S';

    public static final int NON_NEGOTIABLE_LEASE	= 'n';
    public static final int FORCE			= 'f';
    public static final int DELETE_DATA			= 'x';
    public static final int DELETE_TABLES		= 'x';
    public static final int KEEP_TABLES			= 'k';
    public static final int POINT_TO_POINT		= 'b';
    public static final int RESOURCE			= 'r';
    public static final int RESOURCE_CONFIG		= 'u';
    public static final int PATH			= 'p';
    public static final int LEASE_LENGTH		= 'l';
    public static final int DNS_DOMAIN			= 'd';
    public static final int SERVICE_DISABLE		= 'd';
    public static final int DNS_ADDRESSES		= 'a';
    public static final int NIS_ADDRESSES		= 'a';
    public static final int NETWORK_ADDRESSES		= 'a';
    public static final int SUBNET_MASK			= 'm';
    public static final int MACRO_LIST			= 'm';
    public static final int OPTION_LIST			= 'o';
    public static final int ROUTER_ADDRESSES		= 't';
    public static final int NIS_DOMAIN			= 'y';
    public static final int SIGHUP			= 'g';
    public static final int SERVICE_ENABLE		= 'e';
    public static final int SERVICE_REENABLE		= 'r';
    public static final int SERVICE_QUERY		= 'q';

    /**
     * Constructs a dhcpconfig command.
     * @param args the options to the command.
     */
    public DhcpCfg(String args[]) {

	// Set the options.
	//
	options = new DhcpCliOptions();
	this.args = args;

    } // constructor

    /**
     * Returns the manpage signature for the program.
     * @return the manpage signature for the program.
     */
    public String getManPage() {
	return "dhcpconfig(1M)";
    }

    /**
     * Displays program usage.
     */
    public void usage() {

	DhcpCliPrint.printErrMessage(getString("dhcpcfg_usage"));

    } // usage

    /**
     * Executes the program function.
     * @return SUCCESS or FAILURE
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
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("dhcpcfg_invalid_arg"));
		throw new IllegalArgumentException(form.format(arguments));
	    }

	    if (function == null) {
		String msg = getString("dhcpcfg_no_function_error");
		throw new IllegalArgumentException(msg);
	    }

	    function.setOptions(options);
	    function.setStandardOptions();
	    returnCode = function.execute();

	} catch (IllegalArgumentException e) {
	    StringBuffer msg = new StringBuffer(SIGNATURE);
	    msg.append(DhcpCliFunction.getMessage(e));
	    DhcpCliPrint.printErrMessage(msg.toString());
	    DhcpCliPrint.printErrMessage("");
	    usage();
	    returnCode = FAILURE;
	} catch (Throwable e) {
	    StringBuffer msg = new StringBuffer(SIGNATURE);
	    msg.append(DhcpCliFunction.getMessage(e));
	    DhcpCliPrint.printErrMessage(msg.toString());
	    returnCode = FAILURE;
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
	case CONFIGURE_DHCP:
	    setFunction(new ConfigureDhcp());
	    break;
	case CONFIGURE_BOOTP:
	    setFunction(new ConfigureBootp(value));
	    break;
	case UNCONFIGURE_DHCP:
	    setFunction(new UnconfigureDhcp());
	    break;
	case CONFIGURE_NETWORK:
	    setFunction(new ConfigureNetwork(value));
	    break;
	case CONVERT_DATA_STORE:
	    setFunction(new ConvertDataStore());
	    break;
	case EXPORT_DATA:
	    setFunction(new ExportData(value));
	    break;
	case IMPORT_DATA:
	    setFunction(new ImportData(value));
	    break;
	case CONFIGURE_SERVER_PARAMETER:
	    setFunction(new ServerParameter(value));
	    break;
	case CONFIGURE_SERVICE:
	    setFunction(new ConfigureService());
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

	DhcpCfg dhcpconfig = new DhcpCfg(args);
	int returnCode = DhcpCfg.FAILURE;
	if (dhcpconfig.isValidUser()) {
	    returnCode = dhcpconfig.execute();
	}
	System.exit(returnCode);

    } // main

} // DhcpConfig
