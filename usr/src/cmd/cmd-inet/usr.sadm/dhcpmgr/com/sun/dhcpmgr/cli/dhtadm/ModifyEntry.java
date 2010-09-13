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
 * The main class for the "modify entry" functionality of dhtadm.
 */
public class ModifyEntry extends DhtAdmFunction {

    /**
     * The valid options associated with modifying an entry.
     */
    static final int supportedOptions[] = {
	DhtAdm.MACRONAME,
	DhtAdm.SYMBOLNAME,
	DhtAdm.NEWNAME,
	DhtAdm.DEFINITION,
	DhtAdm.EDITSYMBOL,
	DhtAdm.RESOURCE,
	DhtAdm.RESOURCE_CONFIG,
	DhtAdm.PATH,
	DhtAdm.SIGHUP
    };

    /**
     * Constructs a ModifyEntry object.
     */
    public ModifyEntry() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhtAdm.MODIFY_ENTRY);
    }

    /**
     * Executes the "modify entry" functionality.
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

	// Get the modify "sub-functions"
	// One and only one of the options should be set.
	//
	int count = 0;
	String newName = options.valueOf(DhtAdm.NEWNAME);
	if (newName != null) {
	    count++;
	}

	String definition = options.valueOf(DhtAdm.DEFINITION);
	if (definition != null) {
	    count++;
	}

	String editSymbol = options.valueOf(DhtAdm.EDITSYMBOL);
	if (editSymbol != null) {
	    if (symbolName != null) {
		printErrMessage(getString("symbol_edit_error"));
		return (DhtAdm.CRITICAL);
	    }
	    count++;
	}

	if (count != 1) {
	    printErrMessage(getString("modify_no_function_error"));
	    return (DhtAdm.CRITICAL);
	}

	// Get macro or symbol name. One and only one should be set.
	// Then go get the instance of the macro or symbol.
	//
	try {
	    DhcptabRecord oldDhcptabRecord = null;
	    if (macroName != null) {
		oldDhcptabRecord =
		    getDhcptabMgr().getMacro(macroName, getDhcpDatastore());
	    } else if (symbolName != null) {
		oldDhcptabRecord =
			getDhcptabMgr().getOption(symbolName,
			    getDhcpDatastore());
	    } else {
		printErrMessage(getString("internal_error"));
		return (DhtAdm.CRITICAL);
	    }

	    // Identify the function and create the newDhcptabRecord
	    // given the function.
	    //
	    DhcptabRecord newDhcptabRecord = null;

	    if (definition != null) {
		if (macroName != null) {
		    Macro newMacro = new Macro(macroName);
		    newMacro.setValue(definition, false, true);
		    newDhcptabRecord = newMacro;
		} else if (symbolName != null) {
		    newDhcptabRecord =
			getDhcptabMgr().createOption(symbolName, definition);
		} else {
		    printErrMessage(getString("internal_error"));
		    return (DhtAdm.CRITICAL);
		}


	    } else if (newName != null) {
		definition = oldDhcptabRecord.getValue().toString();
		if (macroName != null) {
		    Macro newMacro = new Macro(newName);
		    newMacro.setValue(definition, false, true);
		    newDhcptabRecord = newMacro;
		} else if (symbolName != null) {
		    newDhcptabRecord =
			getDhcptabMgr().createOption(newName, definition);
		} else {
		    printErrMessage(getString("internal_error"));
		    return (DhtAdm.CRITICAL);
		}

	    } else if (editSymbol != null) {

		Macro oldMacro = (Macro)oldDhcptabRecord;
		Macro newMacro = (Macro)oldMacro.clone();
		newMacro.editOption(editSymbol);
		newDhcptabRecord = newMacro;

	    } else {
		printErrMessage(getString("internal_error"));
		return (DhtAdm.CRITICAL);
	    }

	    getDhcptabMgr().modifyRecord(oldDhcptabRecord, newDhcptabRecord,
		false, getDhcpDatastore());
	} catch (NoEntryException e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.ENOENT;
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.WARNING;
	}

	return (returnCode);

    } // execute

} // ModifyEntry
