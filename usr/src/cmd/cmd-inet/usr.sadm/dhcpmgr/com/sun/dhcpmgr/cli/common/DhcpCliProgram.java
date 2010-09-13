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

import java.text.MessageFormat;

/**
 * This class is the base class extended by the DHCP CLI program classes.
 */
public abstract class DhcpCliProgram {

    /**
     * Defines the functionality to be performed.
     */
    protected DhcpCliFunction function = null;
    protected DhcpCliOptions options = null;

    /**
     * Program arguments.
     */
    protected String [] args = null;

    /**
     * Return codes.
     */
    public static final int FAILURE	= -1;
    public static final int SUCCESS	= 0;
    public static final int EXISTS	= 1;
    public static final int ENOENT	= 2;
    public static final int WARNING	= 3;
    public static final int CRITICAL	= 4;

    /**
     * Returns the manpage signature for the program.
     * @return the manpage signature for the program.
     */
    public abstract String getManPage();
    
    /**
     * Uninitializes the program function.
     */
    protected void clearFunction() {
	function = null;
    }

    /**
     * Sets the function that the user has requested.
     * @param function user requested function.
     */
    protected void setFunction(DhcpCliFunction function)
	throws IllegalArgumentException {

	if (this.function != null) {
	    Object [] args = new Object[2];
	    args[0] = DhcpCliOption.getOptionCharacter(
		this.function.getFunctionFlag());
	    args[1] = DhcpCliOption.getOptionCharacter(
		function.getFunctionFlag());
	    String msg = ResourceStrings.getString("multiple_functions");
	    MessageFormat form = new MessageFormat(msg);
	    throw new IllegalArgumentException(form.format(args));
	}

	this.function = function;
    }

    /**
     * Checks to see if the user has permission to run the program.
     * @return true if the user has permission to execute, false otherwise.
     */
    protected boolean isValidUser() {

	// Must be root to run.
        //
        if (!System.getProperty("user.name").equals("root")) {

	    Object [] args = new Object[1];
	    args[0] = getManPage();
	    String msg = ResourceStrings.getString("user_not_allowed");
	    MessageFormat form = new MessageFormat(msg);
	    DhcpCliPrint.printErrMessage(form.format(args));
		
	    return false;
        }
	return true;

    } // isValidUser

} // DhcpCliProgram
