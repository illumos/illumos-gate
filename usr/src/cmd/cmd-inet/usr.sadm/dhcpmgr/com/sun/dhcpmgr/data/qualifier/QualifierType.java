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
 * Common interface for qualifier types.
 */
public interface QualifierType {

    /**
     * Determine if the given string is a legal value for this type.
     *
     * @param value
     *   The value to test.
     * @return
     *   Returns a Java type containing the parsed value if legal, otherwise
     *   null is returned if the value was illegal.
     */
    public Object parseValue(String value);

    /**
     * Format the value into a form that could be offered to parseValue().
     * The validity of the value is implementation dependent. The value
     * passed to formatValue() may result in a non-null result but the same
     * value passed to parseValue() may return null. Also the value returned
     * by formatValue() passed to parseValue() does not guarantee an non-null
     * result from parseValue().
     *
     * @param value
     *   The value to format.
     * @return
     *   Returns a String containing the formatted value or null if the
     *   value could not be formatted correctly.
     */
    public String formatValue(String value);

    /**
     * Get the Java class that is suitable for storing values of the qualifier
     * type.
     *
     *	@return
     *    Suitable Java type for storing values of the qualifier type.
     */
    public Class getJavaType();

    public String toString();

}
