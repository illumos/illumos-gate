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
package com.sun.dhcpmgr.cli.dhcpconfig;

import java.text.MessageFormat;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.data.DhcpdOptions;

/**
 * Abstract class implemented by all the dhcpconfig "function" classes.
 */
public abstract class DhcpCfgFunction
    extends DhcpCliFunction {

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     * @return string from resource bundle.
     */
    public String getString(String key) {

	return ResourceStrings.getString(key);

    } // getString

    /**
     * Determines whether or not the DHCP service is configured.
     * @return true if configured, false if not.
     */
    public boolean isServerConfigured() {

	boolean result = false;

	try {
	    DhcpdOptions opts = getSvcMgr().readDefaults();
	    if (!opts.isRelay()) {
		result = true;
	    }
	} catch (Throwable e) {
	    // nothing to do.
	}

	if (!result) {
	    printErrMessage(getString("dhcpcfg_func_not_configured_error"));
	}

	return (result);

    } // isServerConfigured

    /**
     * Prints a message to the console.
     * @param msg the message to print.
     */
    public void printMessage(String msg) {
	DhcpCliPrint.printMessage(msg);
    } // printMessage

    /**
     * Prints a message to the console..
     * @param msg the message to print.
     */
    public void printMessage(String msg, Object [] arguments) {
        MessageFormat form = new MessageFormat(msg);
	DhcpCliPrint.printMessage(form.format(arguments));
    } // printMessage

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public void printErrMessage(String msg) {
	StringBuffer fullmsg = new StringBuffer(DhcpCfg.SIGNATURE);
	fullmsg.append(msg);
	DhcpCliPrint.printErrMessage(fullmsg.toString());
    } // printErrMessage

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public void printErrMessage(String msg, Object [] arguments) {
	StringBuffer fullmsg = new StringBuffer(DhcpCfg.SIGNATURE);
	fullmsg.append(msg);
        MessageFormat form = new MessageFormat(fullmsg.toString());
	DhcpCliPrint.printErrMessage(form.format(arguments));
    } // printErrMessage

} // DhcpCfgFunction
