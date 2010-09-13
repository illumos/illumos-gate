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
import java.util.ArrayList;

/**
 * An extension of the integer qualifier type that restricts the integer
 * values to a given set.
 */
public class QualifierIntegerEnum extends QualifierInteger
				  implements QualifierEnum {

    /**
     * The set of legal integer values.
     */
    protected int[] values;

    private QualifierIntegerEnum() {}

    /**
     * Construct an integer enumerated qualifier type.
     * 
     * @param values
     *   The set of legal integer values.
     */
    public QualifierIntegerEnum(int[] values) {
	this.values = values;
    }

    /**
     * Get the set of legal integer values.
     * 
     * @return
     *   The set of legal integer values.
     */
    public int[] getValues() {
	return values;
    }

    public Object parseValue(String value) {
	Integer intValue = (Integer) super.parseValue(value);

	if (intValue != null) {
	    int i = intValue.intValue();

	    for (int index = 0; index < values.length; index++) {
		if (values[index] == i) {
		    return intValue;
		}
	    }
	}

	return null;
    }

    public String toString() {
	ArrayList vals = new ArrayList();

	for (int index = 0; index < values.length; index++) {
	    vals.add(new Integer(values[index]));
	}

	return super.toString() + vals;
    }

}
