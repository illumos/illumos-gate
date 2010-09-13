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

import java.util.regex.*;

/**
 * An implementation of the qualifier type that provides a string type
 * where values must be a valid fully qualified domain name.
 */
public class QualifierFQDN extends QualifierString {

    private static final String fqdnRegex = "([a-zA-Z][a-zA-Z0-9-]*[.]?)+";

    public Object parseValue(String value) {
	if (value == null) {
	    return null;
	}

	value = value.trim();

	Pattern pattern = Pattern.compile(fqdnRegex);
	Matcher matcher = pattern.matcher(value);

	if (matcher.matches()) {
	    return value;
	} else {
	    return null;
	}
    }

}
