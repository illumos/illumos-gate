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

/**
 * This class provides methods that may be used to retrieve strings from
 * ResourceBundles and print resulting messages to the console.
 */
public class DhcpCliPrint {

    /**
     * Prints a message to standard output stream.
     * @param msg the message to print.
     */
    public static void printMessage(String msg) {
	System.out.println(msg);
    } // printMessage

    /**
     * Prints a message to the standard error stream.
     * @param msg the message to print.
     */
    public static void printErrMessage(String msg) {
	System.err.println(msg);
    } // printErrMessage

} // DhcpCliPrint
