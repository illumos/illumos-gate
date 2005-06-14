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

/**
 * An extension of the integer qualifier type that restricts the integer
 * values to a given range, bounded by an inclusive minimum and maximum value.
 */
public class QualifierIntegerRange extends QualifierInteger
						    implements QualifierRange {

    /**
     * Minimum legal value.
     */
    protected int min;
    
    /**
     * Maximum legal value.
     */
    protected int max;

    private QualifierIntegerRange() {}

    /**
     * Construct an integer range qualifier type.
     * 
     * @param min
     *   Minimum legal value.
     * @param max
     *   Maximum legal value.
     */
    public QualifierIntegerRange(int min, int max) {
	this.min = min;
	this.max = max;
    }

    /**
     * Get the minimum boundary.
     * 
     * @return
     *   Minimum legal value.
     */
    public int getMin() {
	return min;
    }

    /**
     * Get the maximum boundary.
     * 
     * @return
     *   Maximum legal value.
     */
    public int getMax() {
	return max;
    }

    public Object parseValue(String value) {
	Integer intValue = (Integer)super.parseValue(value);

	if (intValue != null) {
	    int i = intValue.intValue();

	    if (i >= min && i <= max) {
		return intValue;
	    }
	}

	return null;
    }

    public String toString() {
	return super.toString() + "<" + min + "," + max + ">";
    }

}
