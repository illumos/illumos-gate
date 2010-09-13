/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  Opaque.java:   Wrapper for byte[].
//  Author:           James Kempf
//  Created On:       Tue Apr  7 15:21:58 1998
//  Last Modified By: James Kempf
//  Last Modified On: Fri Jun  5 15:26:59 1998
//  Update Count:     38
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The Opaque class wraps Java byte arrays so we can do object-like
 * things, such as deep equality comparison and printing.
 *
 * @author James Kempf
 */

class Opaque extends Object {

    // Character to use for fill.

    private static final char ZERO = '0';

    // The byte array.

    byte[] bytes;

    // For identifying opaques.

    final static String OPAQUE_HEADER = "\\ff";

    // Construct a Opaque.

    Opaque(byte[] nb) {
	bytes = nb;

    }

    // Construct a byte array from an escaped string.

    static byte[] unescapeByteArray(String str)
	throws ServiceLocationException {

	// Check for opaque header.

	if (!str.startsWith(OPAQUE_HEADER)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"no_opaque_header",
				new Object[] {str});

	}

	String string = str.substring(OPAQUE_HEADER.length());

	// Process escapes to remove slash.
	//  string.

	int i, n = string.length();
	int len = 0;
	int nlen = n / 3;
	byte[] b = new byte[nlen];

	for (i = 0; i < n; i++) {
	    if (string.charAt(i) != ServiceLocationAttribute.ESCAPE) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"escape_err",
				new Object[] {str});

	    }

	    // Get the next two characters.

	    if (i > n - 2) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"nonterminating_escape",
				new Object[] {str});
	    }

	    if (len >= nlen) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"wrong_char_num",
				new Object[] {str});
	    }

	    try {

		i++;
		b[len++] = (byte)(Integer.parseInt(
				string.substring(i, i+2), 16) & 0xFF);
		i++;

	    } catch (NumberFormatException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"not_hex",
				new Object[] {str});

	    }

	}

	return b;
    }

    // Overrides Object.equals().

    public boolean equals(Object o) {

	if (o == this) {
	    return true;

	}

	if (!(o instanceof Opaque)) {
	    return false;

	}

	byte[]  cbyte = ((Opaque)o).bytes;

	// Not equal if lengths aren't.

	if (cbyte.length != bytes.length) {
	    return false;

	}

	// Check inside.

	int i;

	for (i = 0; i < cbyte.length; i++) {
	    if (cbyte[i] != bytes[i]) {
		return false;

	    }
	}

	return true;
    }

    public String toString() {

	int i, n = bytes.length;
	StringBuffer buf = new StringBuffer();

	buf.append(OPAQUE_HEADER);

	for (i = 0; i < n; i++) {
	    String str = null;

	    // Convert each byte into a string, then escape. We use
	    //  an 8-bit encoding, LATIN1, since escapes are two
	    //  characters only.

	    str = Integer.toHexString(((int)bytes[i] & 0xFF));

	    buf.append(ServiceLocationAttribute.ESCAPE);

	    if (str.length() < 2) {
		buf.append(ZERO);
	    }

	    buf.append(str);
	}

	return buf.toString();
    }

}
