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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  ServiceLocationAttribute.java : Class for attributes in SLP.
//  Author:           James Kempf, Erik Guttman
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The ServiceLocationAttribute class models SLP attributes.
 *
 * @author James Kempf, Erik Guttman
 */

public class ServiceLocationAttribute extends Object
    implements Serializable {

    // Characters to escape.

    final static String RESERVED = "(),\\!<=>~";
    final static String ESCAPED = RESERVED + "*";
    final static char ESCAPE = '\\';

    final static char CTL_LOWER = (char)0x00;
    final static char CTL_UPPER = (char)0x1F;
    final static char DEL = (char)0x7F;

    // Whitespace chars.

    static final String WHITESPACE = " \n\t\r";
    static final char SPACE = ' ';

    // For character escaping.

    static final char COMMA = ',';
    static final char PERCENT = '%';

    // Bad tag characters.

    final private static String BAD_TAG_CHARS = "*\n\t\r";

    // For identifying booleans.

    final static String TRUE = "true";
    final static String FALSE = "false";

    //
    // Package accessable fields.
    //

    Vector values = null;
    String id = null;

    // For V1 compatibility subclass.

    ServiceLocationAttribute() {}

    /**
     * Construct a service location attribute.
     *
     * @param id		The attribute name
     * @param values_in	Vector of one or more attribute values. Vector
     *			contents must be uniform in type and one of
     *			Integer, String, Boolean, or byte[]. If the attribute
     *			is a keyword attribute, then values_in should be null.
     * @exception IllegalArgumentException Thrown if the
     *			vector contents is not of the right type or
     *			an argument is null or syntactically incorrect.
     */

    public ServiceLocationAttribute(String id_in, Vector values_in)
	throws IllegalArgumentException {

	Assert.nonNullParameter(id_in, "id");

	id = id_in;
	if (values_in != null &&
	    values_in.size() > 0) { // null, empty indicate keyword attribute.

	    values = (Vector)values_in.clone();

	    verifyValueTypes(values, false);

	}
    }

    /**
     * Construct a service location attribute from a parenthesized expression.
     * The syntax is:
     *
     *	 exp = "(" id "=" value-list ")" | keyword
     *    value-list = value | value "," value-list
     *
     *
     * @param exp The expression
     * @param dontTypeCheck True if multivalued booleans and vectors
     *			   of varying types are allowed.
     * @exception ServiceLocationException If there are any syntax errors.
     */

    ServiceLocationAttribute(String exp, boolean allowMultiValuedBooleans)
	throws ServiceLocationException {

	if (exp == null || exp.length() <= 0) {
	    new ServiceLocationException(ServiceLocationException.PARSE_ERROR,
					 "null_string_parameter",
					 new Object[] {exp});

	}

	// If start and end paren, then parse out assignment.

	if (exp.startsWith("(") && exp.endsWith(")")) {

	    StringTokenizer tk =
		new StringTokenizer(exp.substring(1, exp.length() - 1),
				    "=",
				    true);

	    try {

		// Get the tag.

		id =
		    unescapeAttributeString(tk.nextToken(), true);

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

		    Object o = evaluate(value);

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

	    id = unescapeAttributeString(exp, true);

	}
    }

    static Object evaluate(String value)
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
		//  opaque.

		if (val.startsWith(Opaque.OPAQUE_HEADER)) {
		    o = Opaque.unescapeByteArray(val);

		} else {
		    o = unescapeAttributeString(val, false);

		}
	    }
	}

	return o;

    }

    //
    // Property accessors.
    //

    /**
     * @return A vector of attribute values, or null if the attribute is
     *         a keyword attribute. If the attribute is single-valued, then
     *         the vector contains only one object.
     *
     */

    public Vector getValues() {

	if (values == null) {
	    return null;	// keyword case.
	}

	Vector ret = (Vector)values.clone();

	// Need to process Opaques.

	int i, n = ret.size();

	for (i = 0; i < n; i++) {
	    Object o = ret.elementAt(i);

	    if (o instanceof Opaque) {
		o = ((Opaque)o).bytes;

	    }

	    ret.setElementAt(o, i);
	}

	return ret;
    }

    /**
     * @return The attribute name.
     */

    public String getId() {

	return id;

    }

    /**
     * Return an escaped version of the id parameter , suitable for inclusion
     * in a query.
     *
     * @param str The string to escape as an id.
     * @return The string with any reserved characters escaped.
     * @exception IllegalArgumentException Thrown if the
     *			string contains bad tag characters.
     */

    static public String escapeId(String str)
	throws IllegalArgumentException {
	String ret = null;

	try {
	    ret = escapeAttributeString(str, true);

	} catch (ServiceLocationException ex) {
	    throw new IllegalArgumentException(ex.getMessage());

	}

	return ret;
    }

    /**
     * Return an escaped version of the value parameter, suitable for inclusion
     * in a query. Opaques are stringified.
     *
     * @param val The value to escape.
     * @return The stringified value.
     * @exception IllegalArgumentException Thrown if the object is not
     * 	         one of byte[], Integer, Boolean, or String.
     */

    static public String escapeValue(Object val)
	throws IllegalArgumentException {

	// Check type first.

	typeCheckValue(val);

	// Make Opaque out of byte[].

	if (val instanceof byte[]) {
	    val = new Opaque((byte[])val);

	}

	return  escapeValueInternal(val);

    }

    // Check type to make sure it's OK.

    static private void typeCheckValue(Object obj) {
	SLPConfig conf = SLPConfig.getSLPConfig();

	Assert.nonNullParameter(obj, "attribute value vector element");

	if (obj.equals("")) {
	    throw
		new IllegalArgumentException(
				conf.formatMessage("empty_string_value",
						   new Object[0]));
	}

	if (!(obj instanceof Integer) && !(obj instanceof Boolean) &&
	    !(obj instanceof String) && !(obj instanceof byte[])) {
	    throw
		new IllegalArgumentException(
				conf.formatMessage("value_type_error",
						   new Object[0]));
	}

    }

    // We know the value's type is OK, so just escape it.

    private static String escapeValueInternal(Object val) {

	String s;

	// Escape any characters needing it.

	if (val instanceof String) {

	    try {

		s = escapeAttributeString((String)val, false);

	    } catch (ServiceLocationException ex) {
		throw
		    new IllegalArgumentException(ex.getMessage());

	    }

	} else {
	    s = val.toString();

	}

	return s;
    }

    //
    // Methods for dealing with the type of attribute values.
    //

    // Verify the types of incoming attributes.

    protected void
	verifyValueTypes(Vector values_in, boolean dontTypeCheck) {

	SLPConfig conf = SLPConfig.getSLPConfig();

	// Make sure the types of objects passed in are acceptable
	//  and that all objects in the vector have the same type.

	int i, n = values_in.size();
	Class cls = null;

	for (i = 0; i < n; i++) {
	    Object obj = values_in.elementAt(i);

	    typeCheckValue(obj);

	    if (i == 0) {
		cls = obj.getClass();

	    } else if (!cls.equals(obj.getClass()) && !dontTypeCheck) {
		throw
		    new IllegalArgumentException(
				conf.formatMessage("type_mismatch_error",
						   new Object[0]));
	    }

	    // If it's a boolean and there's more than one, signal error
	    // unless multivalued booleans are allowed.

	    if (!dontTypeCheck && i != 0 && obj instanceof Boolean) {
		throw
		    new IllegalArgumentException(
				conf.formatMessage("multivalued_boolean",
						   new Object[0]));

	    }

	    // If it's a byte array, create a Opaque object.

	    if (obj instanceof byte[]) {
		values_in.setElementAt(new Opaque((byte[])obj), i);

	    } else if (obj instanceof String) {
		String val = (String)obj;

		// If it's a string and looks like "1" or "true", then
		//  append a space onto the end.

		try {

		    Object obj2 = evaluate(val);

		    if (!(obj2 instanceof String)) {
			values_in.setElementAt((String)val + " ", i);

		    }

		} catch (ServiceLocationException ex) {

		    // Ignore for now.

		}
	    }
	}

    }

    //
    // Methods for externalizing attributes.
    //

    /**
     * Externalize the attribute into a string that can be written
     * to a byte stream. Includes escaping any characters that
     * need to be escaped.
     *
     * @return String with attribute's external representation.
     * @exception ServiceLocationException Thrown if the
     *			string contains unencodable characters.
     */

    String externalize()
	throws ServiceLocationException {

	if (values == null) {	// keyword attribute...
	    return escapeAttributeString(id, true);
	}

	Vector v = new Vector();

	for (Enumeration e = values.elements(); e.hasMoreElements(); ) {
	    Object o = e.nextElement();
	    String s = null;

	    s = escapeValueInternal(o);

	    v.addElement(s);
	}

	StringBuffer buf =
	    new StringBuffer("(" +
			     escapeAttributeString(id, true) +
			     "=");

	buf.append(SrvLocHeader.vectorToCommaSeparatedList(v));

	buf.append(")");

	return buf.toString();
    }

    //
    // Escaping and unescaping strings.
    //

    /**
     * Escape any escapable characters to a 2 character escape
     * in the attribute string.
     *
     * @param string The String.
     * @param badTag Check for bad tag characters if true.
     * @return The escaped string.
     * @exception ServiceLocationException Thrown if the string
     *			contains a character that can't be encoded.
     */

    static String escapeAttributeString(String string,
					boolean badTag)
	throws ServiceLocationException {

	StringBuffer buf = new StringBuffer();
	int i, n = string.length();

	for (i = 0; i < n; i++) {
	    char c = string.charAt(i);

	    // Check for bad tag characters first.

	    if (badTag && BAD_TAG_CHARS.indexOf(c) != -1) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"bad_id_char",
				new Object[] {Integer.toHexString(c)});
	    }

	    // Escape if the character is reserved.

	    if (canEscape(c)) {
		buf.append(ESCAPE);

		String str = escapeChar(c);

		// Pad with zero if less than 2 characters.

		if (str.length() <= 1) {
		    str = "0" + str;

		}

		buf.append(str);

	    } else {

		buf.append(c);

	    }
	}

	return buf.toString();

    }


    /**
     * Convert any 2 character escapes to the corresponding characters.
     *
     * @param string The string to be processed.
     * @param badTag Check for bad tag characters if true.
     * @return The processed string.
     * @exception ServiceLocationException Thrown if an escape
     *			is improperly formatted.
     */

    static String unescapeAttributeString(String string,
					  boolean badTag)
	throws ServiceLocationException {

	// Process escapes.

	int i, n = string.length();
	StringBuffer buf = new StringBuffer(n);

	for (i = 0; i < n; i++) {
	    char c = string.charAt(i);

	    // Check for escaped characters.

	    if (c == ESCAPE) {

		// Get the next two characters.

		if (i >= n - 2) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"nonterminating_escape",
				new Object[] {string});
		}

		i++;
		c = unescapeChar(string.substring(i, i+2));
		i++;

		// Check whether it's reserved.

		if (!canEscape(c)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"char_not_reserved_attr",
				new Object[] {Character.valueOf(c), string});
		}

	    } else {

		// Check whether the character is reserved.

		if (isReserved(c)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"reserved_not_escaped",
				new Object[] {Character.valueOf(c)});
		}

	    }

	    // If we need to check for a bad tag character, do so now.

	    if (badTag && BAD_TAG_CHARS.indexOf(c) != -1) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"bad_id_char",
				new Object[] {Integer.toHexString(c)});

	    }

	    buf.append(c);

	}

	return buf.toString();
    }

    // Return true if the character c can be escaped.

    private static boolean canEscape(char c) {

	return ((ESCAPED.indexOf(c) != -1) ||
		((c >= CTL_LOWER && c <= CTL_UPPER) || c == DEL));

    }

    // Return true if the character c is reserved.

    private static boolean isReserved(char c) {

	return ((RESERVED.indexOf(c) != -1) ||
		((c >= CTL_LOWER && c <= CTL_UPPER) || c == DEL));

    }

    /**
     * Return a string of integers giving the character's encoding in
     * the character set passed in as encoding.
     *
     * @param c The character to escape.
     * @return The character as a string of integers for the encoding.
     */

    static String escapeChar(char c) {

	byte[] b = null;

	try {

	    b = ("" + c).getBytes(Defaults.UTF8);

	} catch (UnsupportedEncodingException ex) {

	    Assert.slpassert(false, "no_utf8", new Object[0]);

	}

	int code = 0;

	// Assemble the character code.

	if (b.length > 3) {
	    Assert.slpassert(false,
			  "illegal_utf8",
			  new Object[] {Character.valueOf(c)});

	}

	code = (int)(b[0] & 0xFF);

	if (b.length > 1) {
	    code = (int)(code | ((b[1] & 0xFF) << 8));
	}

	if (b.length > 2) {
	    code = (int)(code | ((b[2] & 0xFF) << 16));
	}

	String str = Integer.toHexString(code);

	return str;
    }

    /**
     * Unescape the character encoded as the string.
     *
     * @param ch The character as a string of hex digits.
     * @return The character.
     * @exception ServiceLocationException If the characters can't be
     *		 converted into a hex string.
     */

    static char unescapeChar(String ch)
	throws ServiceLocationException {

	int code = 0;

	try {
	    code = Integer.parseInt(ch, 16);

	} catch (NumberFormatException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"not_a_character",
				new Object[] {ch});
	}

	// Convert to bytes.

	String str = null;
	byte b0 = 0, b1 = 0, b2 = 0, b3 = 0;
	byte b[] = null;

	b0 = (byte) (code & 0xFF);
	b1 = (byte) ((code >> 8) & 0xFF);
	b2 = (byte) ((code >> 16) & 0xFF);
	b3 = (byte) ((code >> 24) & 0xFF);

	// We allow illegal UTF8 encoding so we can decode byte arrays.

	if (b3 != 0) {
	    b = new byte[3];
	    b[3] = b3;
	    b[2] = b2;
	    b[1] = b1;
	    b[0] = b0;
	} else if (b2 != 0) {
	    b = new byte[3];
	    b[2] = b2;
	    b[1] = b1;
	    b[0] = b0;
	} else if (b1 != 0) {
	    b = new byte[2];
	    b[1] = b1;
	    b[0] = b0;
	} else {
	    b = new byte[1];
	    b[0] = b0;
	}

	// Make a string out of it.

	try {
	    str = new String(b, Defaults.UTF8);

	} catch (UnsupportedEncodingException ex) {

	    Assert.slpassert(false, "no_utf8", new Object[0]);

	}

	int len = str.length();

	if (str.length() > 1) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"more_than_one",
				new Object[] {ch});

	}

	return (len == 1 ? str.charAt(0):(char)0);
    }

    /**
     * Merge the values in newAttr into the attribute in the hashtable
     * if a duplicate attribute, signal error if a type mismatch.
     * Both the return vector and hashtable are updated, but the
     * newAttr parameter is left unchanged.
     *
     * @param attr The ServiceLocationAttribute to check.
     * @param attrHash A Hashtable containing the attribute tags as
     *			keys and the attributes as values.
     * @param returns A Vector in which to put the attribute when done.
     * @param dontTypeCheck If this flag is true, the value vector
     *			   may have two booleans, may
     *			   contain differently typed objects, or the
     *			   function may merge a keyword and nonkeyword
     *			   attribute.
     * @exception ServiceLocationException Thrown if a type mismatch
     *			occurs.
     */

    static void
	mergeDuplicateAttributes(ServiceLocationAttribute newAttr,
				 Hashtable attrTable,
				 Vector returns,
				 boolean dontTypeCheck)
	throws ServiceLocationException {

	// Look up the attribute

	String tag = newAttr.getId().toLowerCase();
	ServiceLocationAttribute attr =
	    (ServiceLocationAttribute)attrTable.get(tag);

	// Don't try this trick with ServerAttributes!

	Assert.slpassert((!(attr instanceof ServerAttribute) &&
		       !(newAttr instanceof ServerAttribute)),
		      "merge_servattr",
		      new Object[0]);

	// If the attribute isn't in the hashtable, then add to
	//  vector and hashtable.

	if (attr == null) {
	    attrTable.put(tag, newAttr);
	    returns.addElement(newAttr);
	    return;

	}


	Vector attrNewVals = newAttr.values;
	Vector attrVals = attr.values;

	// If both keywords, nothing further to do.

	if (attrVals == null && attrNewVals == null) {
	    return;

	}

	// If we are not typechecking and one is keyword while the other
	//  is not, then simply merge in the nonkeyword. Otherwise,
	//  throw a type check exception.

	if ((attrVals == null && attrNewVals != null) ||
	    (attrNewVals == null && attrVals != null)) {

	    if (dontTypeCheck) {
		Vector vals = (attrNewVals != null ? attrNewVals:attrVals);
		attr.values = vals;
		newAttr.values = vals;

	    } else {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"attribute_type_mismatch",
				new Object[] {newAttr.getId()});

	    }

	} else {

	    // Merge the two vectors. We type check against the attrVals
	    //  vector, if we are type checking.

	    int i, n = attrNewVals.size();
	    Object o = attrVals.elementAt(0);
	    Class c = o.getClass();

	    for (i = 0; i < n; i++) {
		Object no = attrNewVals.elementAt(i);

		// Check for type mismatch, throw exception if
		//  we are type checking.

		if ((c != no.getClass()) && !dontTypeCheck) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"attribute_type_mismatch",
				new Object[] {newAttr.getId()});

		}

		// If we are typechecking, and we get two opposite
		//  booleans, we need to throw an exception.

		if (no instanceof Boolean && !no.equals(o) && !dontTypeCheck) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"boolean_incompat",
				new Object[] {newAttr.getId()});

		}

		// Add the value if it isn't already there.

		if (!attrVals.contains(no)) {
		    attrVals.addElement(no);

		}
	    }

	    // Set the new attribute's values so they are the same as the old.

	    newAttr.values = attrVals;

	}
    }

    //
    // Object overrides.
    //

    /**
     * Return true if the object equals this attribute.
     */

    public boolean equals(Object o) {

	if (!(o instanceof ServiceLocationAttribute)) {
	    return false;

	}

	if (o == this) {
	    return true;

	}

	ServiceLocationAttribute sla = (ServiceLocationAttribute)o;

	// check equality of contents, deferring check of all values

	Vector vSLA = sla.values;

	if (!sla.getId().equalsIgnoreCase(id)) {
	    return false;

	}

	if (values == null && vSLA == null) {
	    return true;

	}

	if ((values == null && vSLA != null) ||
	    (values != null && vSLA == null)) {
	    return false;

	}

	if (values.size() != vSLA.size()) {
	    return false;

	}

	// Check contents.

	Object oSLA = vSLA.elementAt(0);
	o = values.elementAt(0);

	if (o.getClass() != oSLA.getClass()) {
	    return false;

	}

	int i, n = vSLA.size();

	for (i = 0; i < n; i++) {
	    oSLA = vSLA.elementAt(i);

	    if (!values.contains(oSLA)) {
		return false;

	    }
	}

	return true;
    }

    /**
     * Return a human readable string for the attribute.
     */

    public String toString() {

	StringBuffer s = new StringBuffer("(");

	s.append(id);

	if (values != null) {
	    s.append("=");

	    int i, n = values.size();

	    for (i = 0; i < n; i++) {
		Object o = values.elementAt(i);

		// Identify type.

		if (i == 0) {
		    s.append(o.getClass().getName());
		    s.append(":");

		} else {
		    s.append(",");

		}

		// Stringify object.

		s.append(o.toString());

	    }
	}

	s.append(")");

	return s.toString();
    }

    // Overrides Object.hashCode().

    public int hashCode() {
	return id.toLowerCase().hashCode();

    }

}
