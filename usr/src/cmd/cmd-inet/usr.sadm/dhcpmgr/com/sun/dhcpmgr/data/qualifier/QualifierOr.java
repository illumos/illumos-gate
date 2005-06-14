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
 * This qualifier type allows the logical or of two qualifier types. Care
 * must be taken that the two qualifier types are suitable. For instance
 * if 'or'ing a string and an integer may result in parseValue() returning
 * either a String or an Integer. 
 */
public class QualifierOr extends QualifierTypeImpl {

    protected QualifierType typeA;

    protected QualifierType typeB;

    public QualifierOr(QualifierType typeA, QualifierType typeB) {
	this.typeA = typeA;
	this.typeB = typeB;
    }

    public void setQualifierTypeA(QualifierType typeA) {
	this.typeA = typeA;
    }

    public void setQualifierTypeB(QualifierType typeB) {
	this.typeB = typeB;
    }

    public QualifierType getQualifierTypeA() {
	return typeA;
    }

    public QualifierType getQualifierTypeB() {
	return typeB;
    }

    public Object parseValue(String value) {
	if (!typeA.getJavaType().equals(typeB.getJavaType())) {
	    return null;
	}

	Object objectA = typeA.parseValue(value);
	Object objectB = typeB.parseValue(value);

	if (objectA != null && objectB != null) {
	    return (objectA.equals(objectB)) ? objectA : null;
	} else {
	    return (objectA == null) ? objectB : objectA;
	}
    }

    public String formatValue(String value) {
	if (!typeA.getJavaType().equals(typeB.getJavaType())) {
	    return null;
	}

	String stringA = typeA.formatValue(value);
	String stringB = typeB.formatValue(value);

	if (stringA != null && stringB != null) {
	    return (stringA.equals(stringB)) ? stringA : null;
	} else {
	    return (stringA == null) ? stringB : stringA;
	}
    }

    public Class getJavaType() {
	return typeA.getJavaType();
    }

    public String toString() {
	return "(" + typeA + " || " + typeB + ")";
    }

}
