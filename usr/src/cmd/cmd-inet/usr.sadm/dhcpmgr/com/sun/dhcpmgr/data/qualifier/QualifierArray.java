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

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.StringTokenizer;

/**
 * An an implementation of the qualifier type that provides an array of
 * qualifier types.  The element qualifer type is contained within the array
 * qualifier type.
 */
public class QualifierArray extends QualifierTypeImpl {

    /**
     * The default String of characters that delimit elements in a String
     * representation of the array when it is parsed.
     */
    public static final String DEFAULT_PARSE_DELIM = ", ";

    /**
     * The default String of characters that delimit elements in a String
     * representation of the array when it is formatted.
     */
    public static final String DEFAULT_FORMAT_DELIM = ",";

    /**
     * The type of the arrays elements.
     */
    protected QualifierType type;

    /**
     * The String of characters that delimit elements in a String
     * representation of the array when it is parsed.
     */
    protected String parseDelim = DEFAULT_PARSE_DELIM;

    /**
     * The String of characters that delimit elements in a String
     * representation of the array when it is formatted.
     */
    protected String formatDelim = DEFAULT_FORMAT_DELIM;

    private QualifierArray() {}

    /**
     * Construct an array qualifier type.
     *
     * @param type
     *   The qualifier type of the arrays elements.
     */
    public QualifierArray(QualifierType type) {
	this(type, DEFAULT_PARSE_DELIM, DEFAULT_FORMAT_DELIM);
    }

    /**
     * Construct an array qualifier type.
     *
     * @param type
     *   The qualifier type of the arrays elements.
     * @param delim
     *   The String of characters that delimit elements in a String
     *   representation of the array.
     */
    public QualifierArray(QualifierType type,
			  String parseDelim,
			  String formatDelim) {
	this.type = type;
	this.parseDelim = parseDelim;
	this.formatDelim = formatDelim;
    }

    /**
     * Get the arrays element qualifier type.
     *
     * @areturn
     *   The qualifier type of the arrays elements.
     */
    public QualifierType getElementType() {
	return type;
    }

    /**
     * Determine if the given value is a legal value for this type. The
     * element delimiters are the default or those supplied during
     * construction of the QualifierArray.
     *
     * @param value
     *   The value to test.
     * @return
     *   Returns a Java type containing the parse value if legal, otherwise
     *   null is returned if the value was illegal.
     */
    public Object parseValue(String value) {
	return parseValue(value, parseDelim);
    }

    /**
     * Determine if the given value is a legal value for this type. The
     * element delimiters provided override the use of the defaults or
     * those supplied during the construction of the QualifierArray.
     *
     * @param value
     *   The value to test.
     * @param parseDelim
     *   The String of characters that delimit elements in a String
     *   representation of the array.
     * @return
     *   Returns a Java type containing the parse value if legal, otherwise
     *   null is returned if the value was illegal.
     */
    public Object parseValue(String value, String parseDelim) {
	if (value == null) {
	    return null;
	}

	StringTokenizer tokenizer = new StringTokenizer(value, parseDelim);
	ArrayList elements = new ArrayList();

	while (tokenizer.hasMoreTokens()) {
	    String token = tokenizer.nextToken();
	    Object object = type.parseValue(token);

	    if (object == null) {
		return null;
	    }

	    elements.add(object);
	}

	return elements.toArray(
	    (Object[])Array.newInstance(type.getJavaType(), elements.size()));
    }

    /**
     * Format the given string if it is a legal value for this type. The
     * element delimiters are the default or those supplied during
     * construction of the QualifierArray.
     *
     * @param value
     *   The value to format.
     * @return
     *   Returns a string containing the formatted value if legal, otherwise
     *   null is returned if the value was illegal.
     */
    public String formatValue(String value) {
	return formatValue(value, parseDelim, formatDelim);
    }

    /**
     * Format the given string if it is a legal value for this type. The
     * element delimiters provided override the use of the defaults or
     * those supplied during the construction of the QualifierArray.
     *
     * @param value
     *   The value to format.
     * @param parseDelim
     *   The String of characters that delimit elements in a String
     *   representation of the array when it is parsed.
     * @param formatDelim
     *   The String of characters that delimit elements in a String
     *   representation of the array when it is formatted.
     * @return
     *   Returns a string containing the formatted value if legal, otherwise
     *   null is returned if the value was illegal.
     */
    public String formatValue(String value,
			      String parseDelim,
			      String formatDelim) {

	if (value == null) {
	    return null;
	}

	value = value.trim();

	StringTokenizer tokenizer = new StringTokenizer(value, parseDelim);
	StringBuffer string = new StringBuffer();

	while (tokenizer.hasMoreTokens()) {
	    String token = tokenizer.nextToken();
	    token = type.formatValue(token);

	    if (token == null) {
		return null;
	    }

	    string.append(token);

	    if (tokenizer.hasMoreTokens()) {
		string.append(formatDelim);
	    }
	}

	return string.toString();
    }

    /**
     * Get the String containing the characters that delimit elements in
     * a String representation of the array when it is parsed.
     *
     * @return
     *   Returns a String containing the characters that delimit elements in
     *   a String representation of the array when it is parsed.
     */
    public String getParseDelimiters() {
	return parseDelim;
    }

    /**
     * Get the String containing the characters that delimit elements in
     * a String representation of the array when it is formatted.
     *
     * @return
     *   Returns a String containing the characters that delimit elements in
     *   a String representation of the array when it is formatted.
     */
    public String getFormatDelimiters() {
	return formatDelim;
    }

    public Class getJavaType() {
	return java.lang.reflect.Array.class;
    }

    public String toString() {
	return "[L" + type.getClass().getName() + ";";
    }

}
