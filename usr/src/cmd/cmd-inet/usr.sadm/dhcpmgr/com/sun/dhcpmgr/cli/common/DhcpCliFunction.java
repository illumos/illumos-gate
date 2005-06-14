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
package com.sun.dhcpmgr.cli.common;

import com.sun.dhcpmgr.data.DhcpDatastore;
import com.sun.dhcpmgr.data.Option;
import com.sun.dhcpmgr.data.StandardOptions;
import com.sun.dhcpmgr.server.DhcpMgr;
import com.sun.dhcpmgr.server.DhcpMgrImpl;
import com.sun.dhcpmgr.server.DhcpServiceMgr;
import com.sun.dhcpmgr.server.DhcpNetMgr;
import com.sun.dhcpmgr.server.DhcptabMgr;
import com.sun.dhcpmgr.bridge.*;

import java.lang.IllegalArgumentException;

/**
 * This class is the base class extended by the DHCP CLI subcommand classes.
 */
public abstract class DhcpCliFunction {

    /**
     * The options for the function.
     */
    protected DhcpCliOptions options = null;
    protected int validOptions[];

    /**
     * Handles to the managers.
     */
    static private DhcpMgr dhcpMgr = null;
    static private DhcpNetMgr netMgr = null;
    static private DhcptabMgr dhcptabMgr = null;
    static private DhcpServiceMgr svcMgr = null;

    /**
     * The DhcpDatastore to be used for this function. A value of 'null'
     * means to just use DHCP defaults.
     */
    private DhcpDatastore datastore = null;

    /**
     * Constructor.
     */
    public DhcpCliFunction() {
	dhcpMgr = new DhcpMgrImpl();
    } // constructor

    /**
     * Get a handle to the DhcpNetMgr
     * @return an instance of DhcpNetMgr
     */
    public static DhcpMgr getDhcpMgr() {
	return dhcpMgr;
    } // getDhcpMgr

    /**
     * Get a handle to the DhcpNetMgr
     * @return an instance of DhcpNetMgr
     */
    public static DhcpNetMgr getNetMgr() {
	if (netMgr == null) {
	    netMgr = dhcpMgr.getNetMgr();
	}
	return netMgr;
    } // getNetMgr

    /**
     * Get a handle to the DhcptabMgr
     * @return an instance of DhcptabMgr
     */
    public static DhcptabMgr getDhcptabMgr() {
	if (dhcptabMgr == null) {
	    dhcptabMgr = dhcpMgr.getDhcptabMgr();
	}
	return dhcptabMgr;
    } // getDhcptabMgr

    /**
     * Get a handle to the DhcpServiceMgr
     * @return an instance of DhcpServiceMgr
     */
    public static DhcpServiceMgr getSvcMgr() {
	if (svcMgr == null) {
	    svcMgr = dhcpMgr.getDhcpServiceMgr();
	}
	return svcMgr;
    } // getSvcMgr

    /**
     * Used to execute the subcommand functionality.
     */
    public abstract int execute()
	throws IllegalArgumentException;

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public abstract int getFunctionFlag();

    /**
     * Returns the DhcpDatastore associated with this function.
     * @returns the DhcpDatastore associated with this function.
     */
    public DhcpDatastore getDhcpDatastore() {
	return datastore;
    } // getDhcpDatastore

    /**
     * Sets the DhcpDatastore associated with this function.
     * @param ds the data store
     */
    public void setDhcpDatastore(DhcpDatastore ds) {
	datastore = ds;
    } // setDhcpDatastore

    /**
     * Sets the DhcpDatastore associated with this function.
     * @param r the data store resource
     * @param l the data store location
     * @param a the data store config
     */
    public void setDhcpDatastore(String r, String l, String a) {
	datastore = createDhcpDatastore(r, l, a);
    } // setDhcpDatastore

    /**
     * Create a DhcpDatastore with the given argument values as attributes.
     * @param r the data store resource
     * @param l the data store location
     * @param a the data store config
     * @returns a DhcpDatastore with the given argument values as attributes
     * or null if all arguments are null.
     */
    public DhcpDatastore createDhcpDatastore(String r, String l, String a) {
	return this.createDhcpDatastore(r, l, a, -1);
    } // createDhcpDatastore

    /**
     * Create a DhcpDatastore with the given argument values as attributes.
     * @param r the data store resource
     * @param l the data store location
     * @param a the data store config
     * @param v the data store resource version
     * @returns a DhcpDatastore with the given argument values as attributes
     * or null if all arguments are null.
     */
    public DhcpDatastore createDhcpDatastore(String r, String l, String a,
	int v) {

	DhcpDatastore datastore = null;

	if (r != null || l != null || a != null || v != -1) {
	    datastore = new DhcpDatastore(r, l, a, v);
	}

	return datastore;
    } // createDhcpDatastore

    /**
     * Used to determine whether or not the data store version is valid.
     */
    public boolean isVersionValid(boolean ignoreAbsentDefaults) {

	boolean isValid = false;
	try {
	    isValid = getSvcMgr().isVersionCurrent();
	
	    if (!isValid) {
		printCmnErrMessage("need_to_convert_datastore");
	    }
	} catch (NoDefaultsException e) {
	    if (!ignoreAbsentDefaults) {
		printCmnErrMessage("no_conf_warning");
	    }
	    isValid = true;
	} catch (Throwable e) {
	    printCmnErrMessage(e.getMessage());
	}

	return isValid;

    } // isVersionValid

    /**
     * Used to set the read the STANDARD options from the DHCP inittab and
     * to initialize the StandardOptions table with these options.
     */
    public void setStandardOptions() {
	try {
	   StandardOptions.setAllOptions(getSvcMgr().getInittabOptions(
		Option.ctxts[Option.STANDARD].getCode()));
	} catch (Throwable e) {
	    printCmnErrMessage(e.getMessage());
	}
    } // setStandardOptions

    /**
     * Used to set the options for this function. Validates that the options
     * received were only options that are legitimate for this subcommand.
     * @param options the options object built as a result of parsing
     * command line input.
     */
    public void setOptions(DhcpCliOptions options)
	throws IllegalArgumentException {

	options.validate(validOptions);
	this.options = options;

    } // setOptions

    /**
     * Uses the resourceKey to retrieve a string from a ResourceBundle (if
     * one exists) and prints the string to the console.
     * @param resourceKey the ResourceBundle key value.
     */
    public void printCmnMessage(String resourceKey) {
	DhcpCliPrint.printMessage(ResourceStrings.getString(resourceKey));
    } // printMessage

    /**
     * Uses the resourceKey to retrieve a string from a ResourceBundle (if
     * one exists) and prints the string to the console error stream.
     * @param resourceKey the ResourceBundle key value.
     */
    public void printCmnErrMessage(String resourceKey) {
	DhcpCliPrint.printErrMessage(ResourceStrings.getString(resourceKey));
    } // printErrMessage

    /**
     * Given a Throwable object, returns a message for it.
     * @param e the Throwable object.
     * @returns a message.
     */
    public static String getMessage(Throwable e) {
	String message = e.getMessage();
	if (message == null) {
	    message = e.toString();
	}
	return message;
    } // getMessage

} // DhcpCliFunction
