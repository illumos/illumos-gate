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

import java.text.MessageFormat;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.ExistsException;

import com.sun.dhcpmgr.common.Importer;
import com.sun.dhcpmgr.common.ImportController;

/**
 * The main class for the "import move data" functionality of dhcpconfig.
 */
public class ImportData extends DhcpCfgFunction implements Importer {

    /**
     * The valid options associated with importing data.
     */
    private static final int supportedOptions[] = {
	DhcpCfg.FORCE,
	DhcpCfg.SIGHUP
    };

    /**
     * The name of the import file.
     */
    private String importFile;

    /**
     * Simple constructor
     */
    public ImportData(String importFile) {

	validOptions = supportedOptions;
	this.importFile = importFile;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.IMPORT_DATA);
    }

    /**
     * Executes the "import move data" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() {

	// Make sure that server is configured as a DHCP server.
	//
	if (!isServerConfigured()) {
	    return (DhcpCfg.FAILURE);
	}

	// Check the validity of the data store version.
	//
	if (!isVersionValid(false)) {
	    return (DhcpCfg.FAILURE);
	}

	// Shall we overwrite any existing, conflicting data?
	boolean force = options.isSet(DhcpCfg.FORCE);

	// Create import controller and do the import
	ImportController controller = new ImportController(this, getDhcpMgr());
	controller.setFile(importFile);
	if (!controller.importData(force)) {
	    return (DhcpCfg.FAILURE);
	}

	// Signal server if user requested
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

    public void initializeProgress(int length) {
	// Do nothing
    }

    public void updateProgress(int done, String message) {
	// Just print the message
	printMessage(message);
    }

    public void displayError(String message) {
	Object [] arguments = new Object[1];
	arguments[0] = message;
	printErrMessage(getString("import_error_msg"), arguments);
    }

    public void displayErrors(String msg, String label, ActionError [] errs) {
	printErrMessage(msg);
	String [] args = new String[3];
	args[0] = label;
	MessageFormat form =
	    new MessageFormat(getString("import_action_error"));
	for (int i = 0; i < errs.length; ++i) {
	    args[1] = errs[i].getName();
	    args[2] = errs[i].getException().getMessage();
	    printErrMessage(form.format(args));
	}
    }

} // ImportData
