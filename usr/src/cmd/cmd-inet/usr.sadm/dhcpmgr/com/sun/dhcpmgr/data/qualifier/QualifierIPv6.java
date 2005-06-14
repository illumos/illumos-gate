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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data.qualifier;

import java.util.*;
import java.util.regex.*;

/**
 * An implementation of the qualifier type that provides a string type
 * where values must be a valid IPv6 address.
 */
public class QualifierIPv6 extends QualifierString {

    private static final String fieldRegex = "0*[0-9a-fA-F]{1,4}";

    private static Pattern pattern;

    public Object parseValue(String value) {
	if (value == null) {
	    return null;
	}

	value = value.trim();

	if (value.equals("::")) {
	    return value;
	}

	QualifierIPv4 ipv4 = new QualifierIPv4();
	Matcher matcher;
	int numFields = 0;
	int numZeroFields = 0;
	int numAdjacentZeroFields = 0;
	StringTokenizer tokenizer = new StringTokenizer(value, ":", true);

	while (tokenizer.hasMoreTokens()) {
	    String field = tokenizer.nextToken();

	    if (field == null) {
		return null;
	    } else if (field.equals(":")) {
		numAdjacentZeroFields++;

		if (numAdjacentZeroFields > 2) {
		    return null;
		} else if (numAdjacentZeroFields == 2) {
		    numZeroFields++;

		    if (numZeroFields > 1) {
			return null;
		    }
		}
	    } else {
		numAdjacentZeroFields = 0;
		matcher = pattern.matcher(field);

		if (!matcher.matches()) {
		    Object ipv4Field = ipv4.parseValue(field);

		    if ((ipv4Field != null && tokenizer.countTokens() > 0) ||
			    ipv4Field == null) {
			return null;
		    }
		}

		numFields++;
	    }
	}

	if ((numFields > 0 && numFields < 9) || value.equals("::")) {
	    return value;
	} else {
	    return null;
	}
    }

    static  {
	pattern = Pattern.compile(fieldRegex);
    }
}
