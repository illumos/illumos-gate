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
 * An implementation of the qualifier type that provide a boolean type.
 * The symbolic values for true and false can be set in two ways during
 * object construction. Either no arguments are given the constructor and the
 * Java Boolean.TRUE and Boolean.FALSE are used. Alternatively a pair of
 * Strings can be passed to the constructor, the first representing true
 * and the second false.
 */
public class QualifierBoolean extends QualifierStringEnum {

    /**
     * True value.
     */
    protected String trueValue;

    /**
     * False value.
     */
    protected String falseValue;

    /**
     * Contruct a boolean qualifier type using the Java string representations
     * of true and false.
     */
    public QualifierBoolean() {
	this(Boolean.TRUE.toString(), Boolean.FALSE.toString());
    }

    /**
     * Contruct a boolean qualifier using the supplied string representations
     * of true and false.
     *
     * @param trueValue
     *   True value.
     * @param falseValue
     *   False value.
     */
    public QualifierBoolean(String trueValue, String falseValue) {
	super(new String[] {trueValue, falseValue});

	this.trueValue = trueValue;
	this.falseValue = falseValue;
    }

    /**
     * Get the string representing true.
     *
     * @return
     *   True value.
     */
    public String getTrue() {
	return trueValue;
    }

    /**
     * Get the string representing false.
     *
     * @return
     *   False value.
     */
    public String getFalse() {
	return falseValue;
    }

    public Object parseValue(String value) {
	if (value == null) {
	    return null;
	}

	value = value.trim();

	if (value.equals(trueValue) || value.equals(falseValue)) {
	    return new Boolean(value);
	} else {
	    return null;
	}
    }

    public String formatValue(String value) {
	if (value == null || parseValue(value) == null) {
	    return null;
	}

	return value.trim();
    }

    public Class getJavaType() {
	return Boolean.class;
    }

}
