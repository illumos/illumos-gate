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
 * This class contains common utilites used by the CLI programs.
 */
public class Util
{
    /**
     * Array of hex characters, used by for translations.
     */
    private static final char hexChars[] = {'0', '1', '2', '3', '4', '5', '6',
	'7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Converts an ascii string into a string containing its hex value.
     * @param ascii the ascii representation
     * @return the hex representation
     */
    public static String asciiToHex(String ascii) {

	StringBuffer hex = new StringBuffer();

	if (ascii == null) {
	    return null;
	}

	for (int i = 0; i < ascii.length(); i++) {
	    char aChar = ascii.charAt(i);
	    int ndx = (aChar >> 4) & 0x000f;
	    hex.append(hexChars[ndx]);
	    ndx = aChar & 0x000f;
	    hex.append(hexChars[ndx]);
	}

	return hex.toString();

    } // asciiToHex

} // Util
