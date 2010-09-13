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
import com.sun.dhcpmgr.cli.common.Format;
import com.sun.dhcpmgr.data.Macro;
import com.sun.dhcpmgr.data.Option;
import com.sun.dhcpmgr.bridge.NoTableException;

import java.lang.IllegalArgumentException;

/**
 * The main class for the "display table" functionality of dhtadm.
 */
public class DisplayTable extends DhtAdmFunction {

    /**
     * The valid options associated with displaying the table.
     */
    static final int supportedOptions[] = {
	DhtAdm.RESOURCE,
	DhtAdm.RESOURCE_CONFIG,
	DhtAdm.PATH,
	DhtAdm.SIGHUP
    };

    /**
     * Constructs a DisplayTable object.
     */
    public DisplayTable() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhtAdm.DISPLAY_TABLE);
    }

    /**
     * Executes the "display table" functionality.
     * @return DhtAdm.SUCCESS, DhtAdm.ENOENT, DhtAdm.WARNING, or 
     * DhtAdm.CRITICAL
     */
    public int execute()
	throws IllegalArgumentException {

	int returnCode = DhtAdm.SUCCESS;

	// Retrieve the table contents. Table consists of macros
	// and options ... go get them.
	//
	Macro [] macros = null;
	Option [] options = null;
	try {
	    macros = getDhcptabMgr().getMacros(getDhcpDatastore());
	    options = getDhcptabMgr().getOptions(getDhcpDatastore());
	} catch (NoTableException e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.ENOENT;
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    returnCode = DhtAdm.WARNING;
	}

	if (returnCode == DhtAdm.SUCCESS) {
	    Format.print(System.out, "%-20s\t", getString("Name"));
	    Format.print(System.out, "%-8s\t", getString("Type"));
	    Format.print(System.out, "%s\n", getString("Value"));
	    Format.print(System.out, "%s\n",
		"==================================================");

	    for (int i = 0; macros != null && i < macros.length; i++) {
		Macro macro = macros[i];
		Format.print(System.out, "%-20s\t", macro.getKey());
		Format.print(System.out, "%-8s\t", getString("Macro"));
		Format.print(System.out, "%s\n", macro.getValue());
	    }

	    for (int i = 0; options != null && i < options.length; i++) {
		Option option = options[i];
		Format.print(System.out, "%-20s\t", option.getKey());
		Format.print(System.out, "%-8s\t", getString("Symbol"));
		Format.print(System.out, "%s\n", option.getValue());
	    }
	}

	return (returnCode);

    } // execute

} // DisplayTable
