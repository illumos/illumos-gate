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

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.data.DhcptabRecord;
import com.sun.dhcpmgr.data.Macro;
import com.sun.dhcpmgr.data.Option;
import com.sun.dhcpmgr.bridge.NoEntryException;

import java.lang.IllegalArgumentException;

/**
 * The main class for the "delete entry" functionality of dhtadm.
 */
public class DeleteEntry extends DhtAdmFunction {

    /**
     * The valid options associated with deleting an entry.
     */
    static final int supportedOptions[] = {
	DhtAdm.MACRONAME,
	DhtAdm.SYMBOLNAME,
	DhtAdm.RESOURCE,
	DhtAdm.RESOURCE_CONFIG,
	DhtAdm.PATH,
	DhtAdm.SIGHUP
    };

    /**
     * Constructs a DeleteEntry object.
     */
    public DeleteEntry() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhtAdm.DELETE_ENTRY);
    }

    /**
     * Executes the "delete entry" functionality.
     * @return DhtAdm.SUCCESS, DhtAdm.ENOENT, DhtAdm.WARNING, or 
     * DhtAdm.CRITICAL
     */
    public int execute()
	throws IllegalArgumentException {

	int returnCode = DhtAdm.SUCCESS;

	// Get macro or symbol name. One and only one should be set.
	//
	String macroName = options.valueOf(DhtAdm.MACRONAME);
	String symbolName = options.valueOf(DhtAdm.SYMBOLNAME);

	if (macroName != null && symbolName != null) {
	    String msg = getString("two_keys_error");
	    throw new IllegalArgumentException(msg);
	}

	if (macroName == null && symbolName == null) {
	    String msg = getString("no_keys_error");
	    throw new IllegalArgumentException(msg);
	}

	try {
	    // Get the DhcptabRecord.
	    //
	    DhcptabRecord dhcptabRecord = null;
	    if (macroName != null) {
		dhcptabRecord = new Macro(macroName);
	    } else if (symbolName != null) {
		dhcptabRecord = new Option();
		dhcptabRecord.setKey(symbolName);
	    } else {
		printErrMessage(getString("internal_error"));
		returnCode = DhtAdm.CRITICAL;
	    }

	    // Delete the entry.
	    //
	    if (returnCode == DhtAdm.SUCCESS) {
		getDhcptabMgr().deleteRecord(dhcptabRecord, false,
		    getDhcpDatastore());
	    }

	} catch (NoEntryException e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.ENOENT;
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.WARNING;
	}

	return (returnCode);

    } // execute

} // DeleteEntry
