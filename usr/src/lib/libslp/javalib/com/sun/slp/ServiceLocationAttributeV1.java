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

//  ServiceLocationAttributeV1.java: SLPv1 character encoding and decoding
//  Author:           James Kempf
//  Created On:       Fri Oct  9 19:18:17 1998
//  Last Modified By: James Kempf
//  Last Modified On: Sat Oct 24 13:17:58 1998
//  Update Count:     15
//

package com.sun.slp;

import java.util.*;

/**
 * Handles attribute string encoding and decoding for SLPv1.
 *
 * @author James Kempf
 */

class ServiceLocationAttributeV1 extends ServiceLocationAttribute {

    String charCode = IANACharCode.UTF8;  // how to encode the attribute.

    // Characters to escape.

    final private static String UNESCAPABLE_CHARS = ",=!></*()";
    final private static String ESCAPABLE_CHARS =
	UNESCAPABLE_CHARS + "&#;";

    /**
     * Handles radix64 string encoding and decoding for SLPv1.
     *
     * @author James Kempf
     */

    static class Radix64 extends Object {

	/**
	 * Translates the 6 bit value to the corresponding radix 64
	 * representation.
	 */
	private static char LUT(char cin) {

	    int i = (int)(cin & (char)0x00FF);
	    char result = ' ';

	    if (i < 26) {
		result = (char)((char)i + 'A');

	    } else if (i < 52) {
		result = (char)((char)(i - 26) + 'a');

	    } else if (i < 62) {
		result = (char)((char)(i - 52) + '0');

	    } else if (i == 62) {
		result = '+';

	    } else if (i == 63) {
		result = '/';

	    }

	    return result;
	}

	/**
	 * Translates a radix 64 representation to the 64 bit value which
	 * corresponds to it.
	 */
	private static char LUT2(char cin, String s)
	    throws ServiceLocationException {

	    int i = (int)(cin & 0x00ff);
	    char c = (char) 0xffff;

	    if (((char)i >= 'A') && ((char)i <= 'Z')) {
		c = (char)((char)i - 'A');

	    }

	    if (((char)i >= 'a') && ((char)i <= 'z')) {
		c = (char)((char)i - 'a' +(char) 26);

	    }

	    if (((char)i >= '0') && ((char)i <= '9')) {
		c = (char)((char)i - '0' +(char) 52);

	    }

	    if ((char)i == '+') {
		c = (char)62;

	    }

	    if ((char)i == '/') {
		c = (char)63;

	    }

	    if ((char)i == '=') {
		c = (char)0;

	    }

	    if (c == 0xffff) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});

	    }

	    return c;
	}

	// format of the encoding is "(###:encoding)" where ### is the length

	// convert a string in the encoding to the buffer format

	static Opaque radix64ToOpaque(String s)
	    throws ServiceLocationException {

	    if (s == null || s.trim().length() == 0) {
		return new Opaque(new byte[0]);

	    }

	    int oplen = 0;
	    int scan = 0;

	    while (scan < s.length()) {
		if (s.charAt(scan) == '(') {
		    break;  // scan till begins

		}

		scan++;
	    }

	    scan++; // past the '('

	    while (scan < s.length()) {
		if (Character.isWhitespace(s.charAt(scan)) == false) {
		    break;

		}
		scan++;
	    }

	    while (scan < s.length()) {

		if (Character.isDigit(s.charAt(scan))) {
		    oplen *= 10;
		    oplen += (s.charAt(scan) - '0');
		    scan++;

		} else {
		    break;

		}
	    }

	    if (scan >= s.length()) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});

	    }


	    if (s.charAt(scan) != ':') {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});

	    }

	    scan++; // past the ':'

	    byte b[] = new byte[oplen];

	    int pos = 0;
	    int timesthrough = (oplen/3);

	    if ((oplen %3) != 0) {
		timesthrough++;

	    }

	    for (int i = 0; i < timesthrough; i++) {

		// get 4 bytes to make 3 with, skipping blanks

		char v[] = new char[4];

		for (int x = 0; x < 4; x++) {

		    while ((scan < s.length()) &&
			   Character.isWhitespace(s.charAt(scan))) {
			scan++; // eat white

		    }

		    if (scan >= s.length()) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});

		    }

		    v[x] = LUT2(s.charAt(scan), s);
		    scan++;
		}

		b[pos++] =
		    (byte) (((0x3F & v[0]) << 2) + ((0x30 & v[1]) >> 4));
		if (pos >= oplen) break;
		b[pos++] =
		    (byte) (((0x0F & v[1]) << 4) + ((0x3C & v[2]) >> 2));
		if (pos >= oplen) break;
		b[pos++] = (byte) (((0x03 & v[2]) << 6) + (0x3F & v[3]));

	    } // end of conversion loop

	    if (scan >= s.length()) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});
	    }

	    if (s.charAt(scan) != ')') {// check for too many chars.
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_radix64_error",
				new Object[] {s});

	    }

	    return new Opaque(b);
	}

	// convert an Opaque to the encoding

	static String opaqueToRadix64(Opaque oq) {
	    byte[] b = oq.bytes;

	    if (b == null) {
		return new String("");

	    }

	    StringBuffer sb = new StringBuffer("("+b.length+":");

	    int datalen;
	    int fill = b.length%3;

	    if (fill == 0) {
		datalen = (b.length / 3) * 4;

	    } else {
		datalen = ((b.length / 3) + 1) * 4;

	    }

	    int dataoffset = 0;
	    int more = (b.length%3);

	    if (more != 0) {
		more = 1;

	    }

	    int a[] = new int[4];

	    for (int i = 0; i < ((b.length/3)+more-1); i++) {

		a[0] =   (int)(0xFC & (char)b[ dataoffset    ]) >> 2;
		a[1] =  ((int)(0x03 & (char)b[ dataoffset    ]) << 4) +
		    ((int)(0xF0 & (char)b[ dataoffset + 1]) >> 4);
		a[2] =  ((int)(0x0F & (char)b[ dataoffset + 1]) << 2) +
		    ((int)(0xC0 & (char)b[ dataoffset + 2]) >> 6);
		a[3] =   (int)(0x3F & (char)b[ dataoffset + 2]);

		for (int j = 0; j < 4; j++) {
		    sb.append(LUT((char)a[j]));

		}

		dataoffset += 3;
	    }

	    byte f1 = 0, f2 = 0;

	    if (fill == 0) {
		f1 = b[ dataoffset + 1 ];
		f2 = b[ dataoffset + 2 ];

	    } else if (fill == 2) {
		f1 = b[ dataoffset + 1 ];

	    }

	    a[0] = (int) (0xFC & (char)b[ dataoffset ]) >> 2;
	    a[1] = ((int) (0x03 & (char)b[ dataoffset ]) << 4) +
		((int) (0xF0 & (char)f1) >> 4);
	    a[2] = ((int) (0x0F & (char)f1) << 2) +
		((int) (0xC0 & (char)f2) >> 6);
	    a[3] = (int) (0x3F & (char)f2);

	    for (int j = 0; j < 4; j++) {
		sb.append(LUT((char) a[j]));

	    }

	    sb.append(")");

	    return sb.toString();
	}
    }

    // Create an SLPv1 attribute from a general attribute.

    ServiceLocationAttributeV1(ServiceLocationAttribute attr) {
	id = attr.id;
	values = attr.values;

    }

    // Create an SLPv1 attribute from the parenthesized expression, using
    //  charCode to decode any encodings.

    ServiceLocationAttributeV1(String exp,
			       String charCode,
			       boolean allowMultiValuedBooleans)
	throws ServiceLocationException {
	this.charCode = charCode;

	// If start and end paren, then parse out assignment.

	if (exp.startsWith("(") && exp.endsWith(")")) {

	    StringTokenizer tk =
		new StringTokenizer(exp.substring(1, exp.length() - 1),
				    "=",
				    true);

	    try {

		// Get the tag.

		id =
		    unescapeAttributeString(tk.nextToken(), charCode);

		if (id.length() <= 0) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"null_id",
				new Object[] {exp});
		}

		tk.nextToken();  // get rid of "="

		// Gather the rest.

		String rest = tk.nextToken("");

		// Parse the comma separated list.

		values = SrvLocHeader.parseCommaSeparatedListIn(rest, true);

		// Convert to objects.

		int i, n = values.size();
		Class vecClass = null;

		for (i = 0; i < n; i++) {
		    String value = (String)values.elementAt(i);

		    // Need to determine which type to use.

		    Object o = evaluate(value, charCode);

		    // Convert Opaque to byte array.

		    if (o instanceof Opaque) {
			o = ((Opaque)o).bytes;

		    }

		    values.setElementAt(o, i);

		}

	    } catch (NoSuchElementException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"assignment_syntax_err",
				new Object[] {exp});
	    }

	    verifyValueTypes(values, allowMultiValuedBooleans);

	} else {

	    // Check to make sure there's no parens.

	    if (exp.indexOf('(') != -1 || exp.indexOf(')') != -1) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"assignment_syntax_err",
				new Object[] {exp});
	    }

	    // Unescape the keyword.

	    id = unescapeAttributeString(exp, charCode);

	}
    }

    // Duplicate of the one in ServiceLocatioAttribute, except we use our
    //  unescapeAttributeString.

    static Object evaluate(String value, String charCode)
	throws ServiceLocationException {

	Object o = null;

	// If it can be converted into an integer, then convert it.

	try {

	    o = Integer.valueOf(value);

	} catch (NumberFormatException ex) {

	    // Wasn't an integer. Try boolean.

	    if (value.equalsIgnoreCase(TRUE) ||
		value.equalsIgnoreCase(FALSE)) {
		o = Boolean.valueOf(value);

	    } else {

		// Process the string to remove escapes.

		String val = (String)value;

		// If it begins with the opaque prefix, treat it as an
		//  opaque. Use radix64 parser to convert.

		if (val.startsWith("(")) {
		    o = Radix64.radix64ToOpaque(val);

		} else {
		    o = unescapeAttributeString(val, charCode);

		}
	    }
	}

	return o;

    }

    // Externalize the attribute, using its charCode to encode any reserved
    //  characters.

    String externalize()
	throws ServiceLocationException {

	if (values == null) {	// keyword attribute...
	    return escapeAttributeString(id, charCode);
	}

	Vector v = new Vector();

	for (Enumeration e = values.elements(); e.hasMoreElements(); ) {
	    Object o = e.nextElement();
	    String s = null;

	    s = escapeValueInternal(o, charCode);

	    v.addElement(s);
	}

	StringBuffer buf =
	    new StringBuffer("(" +
			     escapeAttributeString(id, charCode) +
			     "=");

	buf.append(SrvLocHeader.vectorToCommaSeparatedList(v));

	buf.append(")");

	return buf.toString();
    }

    // Exactly like the one in ServiceLocationAttribute, but use our
    //  escapeAttributeString.

    private static String escapeValueInternal(Object val, String charCode) {

	String s;

	// Escape any characters needing it.

	if (val instanceof String) {

	    try {

		s = escapeAttributeString((String)val, charCode);

	    } catch (ServiceLocationException ex) {
		throw
		    new IllegalArgumentException(ex.getMessage());

	    }

	} else if (val instanceof Opaque) {

	    // Convert to radix 64.

	    s = Radix64.opaqueToRadix64((Opaque)val);

	} else {
	    s = val.toString();

	}

	return s;
    }

    // Escape an attribute string with the char code.

    static String escapeAttributeString(String string,
					String charCode)
	throws ServiceLocationException {

	StringBuffer buf = new StringBuffer();
	int i, n = string.length();
	boolean is8bit =
	    (charCode.equals(IANACharCode.ASCII) ||
	    charCode.equals(IANACharCode.LATIN1));

	for (i = 0; i < n; i++) {
	    char c = string.charAt(i);

	    if (ESCAPABLE_CHARS.indexOf(c) != -1) {

		buf.append("&#");
		buf.append(IANACharCode.escapeChar(c, charCode));
		buf.append(";");

	    } else {

		// Need to check ASCII and LATIN1 to make sure that
		//  the character is not outside their range of
		//  representation.

		if (is8bit && (short)c > 255) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_8bit_error",
				new Object[] {new Character(c)});
		}

		buf.append(c);

	    }
	}

	return buf.toString();
    }

    // Unescape attribute string, using charCode for reserved characters.

    static String unescapeAttributeString(String string,
					  String charCode)
	throws ServiceLocationException {

	// Process escapes.

	int i, n = string.length();
	StringBuffer buf = new StringBuffer(n);

	for (i = 0; i < n; i++) {
	    char c = string.charAt(i);

	    // Check for invalids.

	    int idx = -1;

	    if ((idx = UNESCAPABLE_CHARS.indexOf(c)) != -1) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
	    }

	    // Check for escapes.

	    if (c != '&') {

		buf.append(c);

	    } else {

		// Check to be sure we've got enough characters left. We need
		// at least 3.

		if ((i + 1) >= n) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
		}

		c = string.charAt(++i);

		if (c != '#') {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
		}

		// Iterate through numbers, collecting.

		StringBuffer num = new StringBuffer(n);

		for (i++; i < n; i++) {

		    c = string.charAt(i);

		    if (!Character.isDigit(c)) {
			break;
		    }

		    num.append(c);
		}

		// If the buffer is empty, then throw exception

		if (num.length() <= 0) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
		}

		// If the last one isn't ";", we've got a problem.

		if (c != ';') {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
		}

		// OK, now convert to a character and add to buffer.

		try {
		    buf.append(IANACharCode.unescapeChar(num.toString(),
							 charCode));

		} catch (NumberFormatException ex) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_escape_error",
				new Object[] {string});
		}
	    }
	}

	return buf.toString();
    }
}
