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
package com.sun.dhcpmgr.cli.dhtadm;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;

/**
 * Abstract class implemented by all the dhtadm "function" classes.
 */
public abstract class DhtAdmFunction
    extends DhcpCliFunction {

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     */
    public String getString(String key) {

	return ResourceStrings.getString(key);

    } // getString

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public void printErrMessage(String msg) {
	StringBuffer fullmsg = new StringBuffer(DhtAdm.SIGNATURE);
	fullmsg.append(msg);
	DhcpCliPrint.printErrMessage(fullmsg.toString());
    } // printErrMessage

} // DhtAdmFunction
