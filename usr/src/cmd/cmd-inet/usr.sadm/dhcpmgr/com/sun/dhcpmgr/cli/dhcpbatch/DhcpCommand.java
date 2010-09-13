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
package com.sun.dhcpmgr.cli.dhcpbatch;

import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliProgram;
import com.sun.dhcpmgr.cli.dhtadm.DhtAdm;
import com.sun.dhcpmgr.cli.pntadm.PntAdm;

/**
 * This class represents a DHCP CLI command.
 */
public class DhcpCommand {

    /**
     * The dhtadm CLI command.
     */
    public static String DHTADM = "dhtadm";
    public static DhtAdm dhtadm = null;

    /**
     * The pntadm CLI command.
     */
    public static String PNTADM = "pntadm";
    public static PntAdm pntadm = null;

    private String [] arglist;

    /**
     * The constructor for a DhcpCommand.
     */
    public DhcpCommand() {
	// nothing to do.
    } // constructor

    /**
     * Sets the arglist for the command.
     * @param input the batch input line.
     */
    public void init(String input) throws BridgeException {
	arglist = DhcpCliFunction.getSvcMgr().getArguments(input);
    } // reset

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     * @return string from resource bundle.
     */
    public String getString(String key) {
	return ResourceStrings.getString(key);
    } // getString

    /**
     * Get the name of the CLI program.
     * @return the name of the CLI for this command.
     */
    public String getProgram() {

	String program = null;
	if (arglist.length != 0) {
	    program = arglist[0];
	}

	return program;

    } // getProgram

    /**
     * Returns the arguments for the CLI.
     * @return the arguments.
     */
    public String [] getArgs() {

	String [] args = new String[arglist.length - 1];

	System.arraycopy(arglist, 1, args, 0, arglist.length - 1);
	return args;

    } // getArgs

    /**
     * Executes the CLI.
     * @return return code as returned by caller.
     */
    public int execute() {
	String program = getProgram();
	String [] args = getArgs();
	int returnCode = DhcpCliProgram.SUCCESS;

	if (program == null) {
	    Object [] arguments = new Object[1];
	    arguments[0] = program;
	    DhcpBatch.printErrMessage(getString("dhcpcommand_invalid_command"),
		arguments);
	} else if (program.equals(PNTADM)) {
	    if (pntadm == null) {
		pntadm = new PntAdm(args);
	    } else {
		pntadm.reset(args);
	    }
	    returnCode = pntadm.execute();
	} else if (program.equals(DHTADM)) {
	    if (dhtadm == null) {
		dhtadm = new DhtAdm(args);
	    } else {
		dhtadm.reset(args);
	    }
	    returnCode = dhtadm.execute();
	} else {
	    Object [] arguments = new Object[1];
	    arguments[0] = program;
	    DhcpBatch.printErrMessage(getString("dhcpcommand_invalid_command"),
		arguments);
	    returnCode = DhcpCliProgram.FAILURE;
	}
	return (returnCode);
    } // execute

} // DhcpCommand
