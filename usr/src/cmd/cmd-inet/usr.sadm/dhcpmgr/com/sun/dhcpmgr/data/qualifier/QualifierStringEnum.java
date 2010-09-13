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

import java.util.Arrays;

/**
 * An extension of the string qualifier type that restricts the string
 * values to a given set.
 */
public class QualifierStringEnum extends QualifierString
				 implements QualifierEnum {

    /**
     * The set of legal string values.
     */
    protected String[] values;

    private QualifierStringEnum() {}

    /**
     * Construct an string enumerated qualifier type.
     * 
     * @param values
     *   The set of legal string values.
     */
    public QualifierStringEnum(String[] values) {
	this.values = values;
    }

    /**
     * Get the set of legal string values.
     * 
     * @return
     *   The set of legal string values.
     */
    public String[] getValues() {
	return values;
    }

    public Object parseValue(String value) {
	if (value != null && Arrays.asList(values).contains(value)) {
	    return value;
	} else {
	    return null;
	}
    }

    public String toString() {
	return super.toString() + Arrays.asList(values);
    }

}
