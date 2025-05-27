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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  AttributeVerifier.java: An attribute verifier for SLP attributes.
//  Author:           James Kempf
//  Created On:       Thu Jun 19 10:51:32 1997
//  Last Modified By: James Kempf
//  Last Modified On: Mon Nov  9 10:21:02 1998
//  Update Count:     200
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The AttributeVerifier class implements the ServiceLocationAttributeVerifier
 * interface, but without committment to a particular mechanism for
 * obtaining the template defintion. Subclasses provide the mechanism,
 * and pass in the template to the parent as a Reader during object
 * creation. The AttributeVerifier class parses tokens from the Reader and
 * constructs the attribute descriptor objects describing the attribute. These
 * are used during verification of the attribute. The AttributeVerifier
 * and implementations of the attribute descriptors are free to optimize
 * space utilization by lazily evaluating portions of the attribute
 * template.
 *
 * @author James Kempf
 *
 */

class AttributeVerifier
    extends Object
    implements ServiceLocationAttributeVerifier {

    // Template specific escape.

    private static final String ESC_HASH = "\\23";
    private static final String HASH = "#";

    // Number of template attributes.

    private static final int TEMPLATE_ATTR_NO = 5;

    // Bitfields for found template attributes.

    private static final int SERVICE_MASK = 0x01;
    private static final int VERSION_MASK = 0x02;
    private static final int DESCRIPTION_MASK = 0x08;
    private static final int URL_PATH_RULES_MASK = 0x10;

    // When all template attribute assignments are found.

    private static final int TEMPLATE_FOUND = (SERVICE_MASK |
					       VERSION_MASK |
					       DESCRIPTION_MASK |
					       URL_PATH_RULES_MASK);

    // These are the valid SLP types.

    private static final String INTEGER_TYPE = "integer";
    private static final String STRING_TYPE = "string";
    private static final String BOOLEAN_TYPE = "boolean";
    private static final String OPAQUE_TYPE = "opaque";
    private static final String KEYWORD_TYPE = "keyword";

    // These are the corresponding Java types. Package public so
    //  others (SLPConfig for example) can get at them.

    static final String JAVA_STRING_TYPE =
	"java.lang.String";
    static final String JAVA_INTEGER_TYPE =
	"java.lang.Integer";
    static final String JAVA_BOOLEAN_TYPE =
	"java.lang.Boolean";
    static final String JAVA_OPAQUE_TYPE =
	"[B";

    // Tokens for boolean values.

    private static final String TRUE_TOKEN = "true";
    private static final String FALSE_TOKEN = "false";

    // This is the number of flags.

    private static final int FLAG_NO = 4;

    // These are the flags.

    private static final String MULTIPLE_FLAG = "m";
    private static final String LITERAL_FLAG = "l";
    private static final String EXPLICIT_FLAG = "x";
    private static final String OPTIONAL_FLAG = "o";

    // These masks help determine whether the flags have been duplicated.

    private static final byte MULTIPLE_MASK = 0x01;
    private static final byte LITERAL_MASK = 0x02;
    private static final byte EXPLICIT_MASK = 0x04;
    private static final byte OPTIONAL_MASK = 0x08;

    // These are tokens for separator characters.

    private static final char TT_COMMA = ',';
    private static final char TT_EQUALS = '=';
    private static final char TT_FIELD = '#';
    private static final char TT_ESCAPE = '\\';

    // This token is for checking version number
    // attribute assignment.

    private static final char TT_PERIOD = '.';

    // Radix64 code characters.

    private static final char UPPER_START_CODE = 'A';
    private static final char UPPER_END_CODE = 'Z';
    private static final char LOWER_START_CODE = 'a';
    private static final char LOWER_END_CODE = 'z';
    private static final char NUMBER_START_CODE = '0';
    private static final char NUMBER_END_CODE = '9';
    private static final char EXTRA_CODE1 = '+';
    private static final char EXTRA_CODE2 = '/';
    private static final char PAD_CODE = '=';
    private static final char LENGTH_SEPERATOR = ':';

    // The SLP service type of this template.

    private ServiceType serviceType;

    // The template's language locale.

    private Locale locale;

    // The template's version.

    private String version;

    // The template's URL syntax.

    private String URLSyntax;

    // The template's description.

    private String description;

    // The attribute descriptors.

    private Hashtable attributeDescriptors = new Hashtable();

    //
    // Constructors.

    AttributeVerifier() {

    }

    // Initialize the attribute verifier with a reader. Subclasses or clients
    // pass in a Reader on the template that is used for parsing. This
    // method is used when the template includes the template attributes
    // and URL rules.

    void initialize(Reader r) throws ServiceLocationException {

	// Use a StreamTokenizer to parse.

	StreamTokenizer tk = new StreamTokenizer(r);

	// Initialize tokenizer for parsing main.

	initFieldChar(tk);

	// Now parse the attribute template, including template attributes.

	parseTemplate(tk);
    }

    // Initialize with this method when no template attributes are involved.

    void initializeAttributesOnly(Reader r)
	throws ServiceLocationException {

	// Use a StreamTokenizer to parse.

	StreamTokenizer tk = new StreamTokenizer(r);

	// Initialize tokenizer for parsing main.

	initFieldChar(tk);

	// Now parse the attribute templates, but no template attributes.

	parseAttributes(tk);
    }

    //
    // ServiceLocationAttributeVerifier interface implementation.
    //

    /**
     * Returns the SLP service type for which this is the verifier.
     *
     * @return The SLP service type name.
     */

    public ServiceType getServiceType() {

	return serviceType;
    }

    /**
     * Returns the SLP language locale of this is the verifier.
     *
     * @return The SLP language locale.
     */

    public Locale getLocale() {

	return locale;
    }

    /**
     * Returns the SLP version of this is the verifier.
     *
     * @return The SLP version.
     */

    public String getVersion() {

	return version;
    }

    /**
     * Returns the SLP URL syntax of this is the verifier.
     *
     * @return The SLP URL syntax.
     */

    public String getURLSyntax() {

	return URLSyntax;
    }

    /**
     * Returns the SLP description of this is the verifier.
     *
     * @return The SLP description.
     */

    public String getDescription() {

	return description;
    }

    /**
     * Returns the ServiceLocationAttributeDescriptor object for the
     * attribute having the named id. IF no such attribute exists in the
     * template, returns null. This method is primarily for GUI tools to
     * display attribute information. Programmatic verification of attributes
     * should use the verifyAttribute() method.
     *
     * @param attrId Id of attribute to return.
     * @return The ServiceLocationAttributeDescriptor object corresponding
     * 	     to the parameter, or null if none.
     */

    public ServiceLocationAttributeDescriptor
	getAttributeDescriptor(String attrId) {

	return
	    (ServiceLocationAttributeDescriptor)
	    attributeDescriptors.get(attrId.toLowerCase());

    }

    /**
     * Returns an Enumeration of
     * ServiceLocationAttributeDescriptors for the template. This method
     * is primarily for GUI tools to display attribute information.
     * Programmatic verification of attributes should use the
     * verifyAttribute() method. Note that small memory implementations
     * may want to implement the Enumeration so that attributes are
     * parsed on demand rather than at creation time.
     *
     * @return A Dictionary with attribute id's as the keys and
     *	      ServiceLocationAttributeDescriptor objects for the
     *	      attributes as the values.
     */

    public Enumeration getAttributeDescriptors() {

	return ((Hashtable)attributeDescriptors.clone()).elements();

    }

    /**
     * Verify that the attribute parameter is a valid SLP attribute.
     *
     * @param attribute The ServiceLocationAttribute to be verified.
     */

    public void verifyAttribute(ServiceLocationAttribute attribute)
	throws ServiceLocationException {

	String id = attribute.getId().toLowerCase();
	ServiceLocationAttributeDescriptor des =
	    (ServiceLocationAttributeDescriptor)attributeDescriptors.get(id);

	if (des == null) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_no_attribute",
				new Object[] { id });
	}


	String type = des.getValueType();
	Vector vals = attribute.getValues();

	// If keyword, check that no values were specified.

	if (des.getIsKeyword()) {

	    if (vals != null) {
		throw
		    new ServiceLocationException(
					 ServiceLocationException.PARSE_ERROR,
					 "template_not_null",
					 new Object[] { id });
	    }
	} else {

	    int i, n;

	    // Check that a values vector exists, and, if the attribute is
	    //  not multivalued, only one element is in it.

	    if (vals == null) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_null",
				new Object[] { id });

	    }

	    n = vals.size();

	    if (n > 1 && !des.getIsMultivalued()) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_not_multi",
				new Object[] { id });
	    }

	    // Get allowed values.

	    Vector av = null;
	    Enumeration en = des.getAllowedValues();

	    if (en.hasMoreElements()) {
		av = new Vector();

		while (en.hasMoreElements()) {
		    Object v = en.nextElement();

		    // Lower case if string, convert to Opaque if byte array.

		    if (type.equals(JAVA_STRING_TYPE)) {
			v = ((String)v).toLowerCase();

		    } else if (type.equals(JAVA_OPAQUE_TYPE)) {
			v = new Opaque((byte[])v);

		    }
		    av.addElement(v);

		}
	    }

	    // Check that the types of the values vector match the attribute
	    //  type. Also, if any allowed values, that attribute values
	    //  match.

	    String attTypeName = des.getValueType();

	    for (i = 0; i < n; i++) {
		Object val = vals.elementAt(i);

		String typeName = val.getClass().getName();

		if (!typeName.equals(attTypeName)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_type_mismatch",
				new Object[] { id, typeName, attTypeName });

		}

		// Convert value for comparison, if necessary.

		if (type.equals(JAVA_STRING_TYPE)) {
		    val = ((String)val).toLowerCase();

		} else if (type.equals(JAVA_OPAQUE_TYPE)) {
		    val = new Opaque((byte[])val);

		}

		if (av != null && !av.contains(val)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_not_allowed_value",
				new Object[] {id, val});

		}
	    }

	}

	// No way to verify `X' because that's a search property. We
	//  must verify `O' in the context of an attribute set.
    }

    /**
     * Verify that the set of registration attributes matches the
     * required attributes for the service.
     *
     * @param attributeVector A Vector of ServiceLocationAttribute objects
     *			     for the registration.
     * @exception ServiceLocationException Thrown if the
     *		 attribute set is not valid. The message contains information
     *		 on the attribute name and problem.
     */

    public void verifyRegistration(Vector attributeVector)
	throws ServiceLocationException {

	Assert.nonNullParameter(attributeVector, "attributeVector");


	if (attributeVector.size() <= 0) {

	    // Check whether any attributes are required. If so, then
	    // there's an error.

	    Enumeration en = attributeDescriptors.elements();

	    while (en.hasMoreElements()) {
		ServiceLocationAttributeDescriptor attDesc =
		    (ServiceLocationAttributeDescriptor)en.nextElement();

		if (!attDesc.getIsOptional()) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_missing_required",
				new Object[] { attDesc.getId() });
		}
	    }
	} else {

	    // Construct a hashtable of incoming objects, verifying them
	    // while doing so.

	    int i, n = attributeVector.size();
	    Hashtable incoming = new Hashtable();

	    for (i = 0; i < n; i++) {
		ServiceLocationAttribute attribute =
		    (ServiceLocationAttribute)attributeVector.elementAt(i);
		String id = attribute.getId().toLowerCase();

		// If we already have it, signal a duplicate.

		if (incoming.get(id) != null) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_dup",
				new Object[] { attribute.getId() });

		}

		verifyAttribute(attribute);

		incoming.put(id, attribute);
	    }

	    // Now check that all required attributes are present.

	    Enumeration en = attributeDescriptors.elements();

	    while (en.hasMoreElements()) {
		ServiceLocationAttributeDescriptor attDesc =
		    (ServiceLocationAttributeDescriptor)en.nextElement();
		String attrId = attDesc.getId();

		if (!attDesc.getIsOptional() &&
		    incoming.get(attrId.toLowerCase()) == null) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_missing_required",
				new Object[] { attrId });
		}
	    }
	}

    }

    //
    // Private implementation. This is the template attribute parser.
    //

    //
    // Tokenizer initializers.

    // Base initialization. Resets syntax tables, sets up EOL parsing,
    //  and makes word case significant.

    private void initForBase(StreamTokenizer tk) {

	// Each part of an attribute production must specify which
	//  characters belong to words.

	tk.resetSyntax();

	// Note that we have to make EOL be whitespace even if significant
	//  because otherwise the line number won't be correctly incremented.

	tk.whitespaceChars((int)'\n', (int)'\n');

	// Don't lower case tokens.

	tk.lowerCaseMode(false);
    }

    // Initialize those token characters that appear in all
    //  productions.

    private void initCommonToken(StreamTokenizer tk) {

	// These characters are recognized as parts of tokens.

	tk.wordChars((int)'A', (int)'Z');
	tk.wordChars((int)'a', (int)'z');
	tk.wordChars((int)'0', (int)'9');
	tk.wordChars((int)'&', (int)'&');
	tk.wordChars((int)'*', (int)'*');
	tk.wordChars((int)':', (int)':');
	tk.wordChars((int)'-', (int)'-');
	tk.wordChars((int)'_', (int)'_');
	tk.wordChars((int)'$', (int)'$');
	tk.wordChars((int)'+', (int)'+');
	tk.wordChars((int)'@', (int)'@');
	tk.wordChars((int)'.', (int)'.');
	tk.wordChars((int)'|', (int)'|');
	tk.wordChars((int)'<', (int)'<');
	tk.wordChars((int)'>', (int)'>');
	tk.wordChars((int)'~', (int)'~');

    }

    // Initialize tokenizer for parsing attribute name,
    // attribute type and flags,
    // and for boolean initializer lists.

    private void initIdChar(StreamTokenizer tk) {

	initForBase(tk);
	initCommonToken(tk);

	// Need backslash for escaping.

	tk.wordChars((int)'\\', (int)'\\');

	// Attribute id, Type, flags, and boolean initialzers
	//  all ignore white space.

	tk.whitespaceChars((int)' ', (int)' ');
	tk.whitespaceChars((int)'\t', (int)'\t');

	// Attribute part won't view newline as being significant.

	tk.eolIsSignificant(false);

	// Case is not folded.

	tk.lowerCaseMode(false);
    }

    // Initialize tokenizer for parsing service type name.
    //  need to restrict characters.

    private void initSchemeIdChar(StreamTokenizer tk) {

	initForBase(tk);

	tk.wordChars((int)'A', (int)'Z');
	tk.wordChars((int)'a', (int)'z');
	tk.wordChars((int)'0', (int)'9');
	tk.wordChars((int)'-', (int)'-');
	tk.wordChars((int)'+', (int)'+');
	tk.wordChars((int)'.', (int)'.');  // allows naming authority.
	tk.wordChars((int)':', (int)':');  // for abstract and concrete type.

	// Scheme name, type, flags, and boolean initialzers
	//  all ignore white space.

	tk.whitespaceChars((int)' ', (int)' ');
	tk.whitespaceChars((int)'\t', (int)'\t');

	// Scheme part won't view newline as being significant.

	tk.eolIsSignificant(false);

	// Case is not folded.

	tk.lowerCaseMode(false);

    }

    // Initialize tokenizer for string list parsing.
    //  Everything except '#' and ',' is recognized.
    //  Note that whitespace is significant, but
    //  EOL is ignored.

    private void initStringItemChar(StreamTokenizer tk) {

	initForBase(tk);

	tk.wordChars((int)'\t', (int)'\t');
	tk.wordChars((int)' ', (int)'"');
	// '#' goes here
	tk.wordChars((int)'$', (int)'+');
	// ',' goes here
	tk.wordChars((int)'-', (int)'/');
	tk.wordChars((int)'0', (int)'9');
	tk.wordChars((int)':', (int)':');
	// ';' goes here
	tk.wordChars((int)'<', (int)'@');
	tk.wordChars((int)'A', (int)'Z');
	tk.wordChars((int)'[', (int)'`');
	tk.wordChars((int)'a', (int)'z');
	tk.wordChars((int)'{', (int)'~');

	// '%' is also reserved, but it is postprocessed
	// after the string is collected.

	// Parse by lines to check when we've reached the end of the list.

	tk.whitespaceChars((int)'\r', (int)'\r');
	tk.whitespaceChars((int)'\n', (int)'\n');
	tk.eolIsSignificant(true);

    }

    // Initialize tokenizer for integer list parsing.

    private void initIntItemChar(StreamTokenizer tk) {

	initForBase(tk);

	tk.wordChars((int)'0', (int)'9');
	tk.wordChars((int)'-', (int)'-');
	tk.wordChars((int)'+', (int)'+');

	// Integer value list parsing ignores white space.

	tk.whitespaceChars((int)' ', (int)' ');
	tk.whitespaceChars((int)'\t', (int)'\t');

	// Parse by lines so we can find the end.

	tk.whitespaceChars((int)'\r', (int)'\r');
	tk.whitespaceChars((int)'\n', (int)'\n');
	tk.eolIsSignificant(true);

    }

    // Boolean lists have same item syntax as scheme char.

    // Initialize main production parsing. The only
    //  significant token character is <NL> because
    //  parsing is done on a line-oriented basis.

    private void initFieldChar(StreamTokenizer tk) {

	initForBase(tk);

	tk.wordChars((int)'\t', (int)'\t');
	tk.wordChars((int)' ', (int)'/');
	tk.wordChars((int)'0', (int)'9');
	tk.wordChars((int)':', (int)'@');
	tk.wordChars((int)'A', (int)'Z');
	tk.wordChars((int)'[', (int)'`');
	tk.wordChars((int)'a', (int)'z');
	tk.wordChars((int)'{', (int)'~');

	tk.whitespaceChars((int)'\r', (int)'\r');
	tk.whitespaceChars((int)'\n', (int)'\n');
	tk.eolIsSignificant(true);
    }

    //
    // Parsing methods.
    //

    // Parse a template from the tokenizer.

    private void parseTemplate(StreamTokenizer tk)
	throws ServiceLocationException {

	// First parse past the template attributes.

	parseTemplateAttributes(tk);

	// Finally, parse the attributes.

	parseAttributes(tk);

    }

    // Parse the template attributes from the tokenizer.

    private void parseTemplateAttributes(StreamTokenizer tk)
	throws ServiceLocationException {

	int found = 0;

	// Parse each of the template attributes. Note that we are parsing
	//  the attribute value assignments, not definitions.

	try {

	    do {

		found = found | parseTemplateAttribute(tk, found);

	    } while (found != TEMPLATE_FOUND);

	} catch (IOException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"template_io_error",
				new Object[] {Integer.toString(tk.lineno())});

	}
    }

    // Parse a template attribute.

    private int parseTemplateAttribute(StreamTokenizer tk, int found)
	throws ServiceLocationException, IOException {

	// Get line including id and equals.

	int tt = tk.nextToken();

	if (tt != StreamTokenizer.TT_WORD) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_assign_error",
				new Object[] {Integer.toString(tk.lineno())});
	}

	// Get tokenizer for id and potential value line.

	StringReader rdr = new StringReader(tk.sval);
	StreamTokenizer stk = new StreamTokenizer(rdr);

	initIdChar(stk);

	// Make sure newline is there.

	if ((tt = tk.nextToken()) == StreamTokenizer.TT_EOF) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

	}

	if (tt != StreamTokenizer.TT_EOL) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

	}


	// Parse off id.

	if ((tt = stk.nextToken()) != StreamTokenizer.TT_WORD) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_missing_id",
				new Object[] {Integer.toString(tk.lineno())});
	}

	String id = stk.sval;
	boolean duplicate = false;
	int mask = 0;

	// Check for the equals.

	if ((tt = stk.nextToken()) != TT_EQUALS) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_missing_eq ",
				new Object[] {Integer.toString(tk.lineno())});

	}

	// Depending on the id, parse the rest.

	if (id.equalsIgnoreCase(SLPTemplateRegistry.SERVICE_ATTR_ID)) {

	    if ((found & SERVICE_MASK) == 0) {

		// Just need to parse off the service type.

		if ((tt = stk.nextToken()) != StreamTokenizer.TT_WORD) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_srv_type_err",
				new Object[] {Integer.toString(tk.lineno())});
		}

		// Check for characters which are not alphanumerics, + and -.
		//  Service type names are more heavily restricted.

		StreamTokenizer sttk =
		    new StreamTokenizer(new StringReader(stk.sval));

		initSchemeIdChar(sttk);

		if (sttk.nextToken() != StreamTokenizer.TT_WORD ||
		    !stk.sval.equals(sttk.sval)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_srv_type_err",
				new Object[] {Integer.toString(tk.lineno())});

		}

		// Need to prefix with "serivce:".

		String typeName = sttk.sval;

		if (!typeName.startsWith(Defaults.SERVICE_PREFIX+":")) {
		    typeName = Defaults.SERVICE_PREFIX+":"+typeName;

		}

		// Set service type instance variable.

		serviceType = new ServiceType(typeName);

		// Check for extra stuff.

		if ((tt = stk.nextToken()) != StreamTokenizer.TT_EOF) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_srv_type_err",
				new Object[] {Integer.toString(tk.lineno())});
		}

		mask = SERVICE_MASK;
	    } else {

		duplicate = true;
	    }
	} else if (id.equalsIgnoreCase(SLPTemplateRegistry.VERSION_ATTR_ID)) {

	    if ((found & VERSION_MASK) == 0) {

		// Just need to parse off the version number.

		if ((tt = stk.nextToken()) != StreamTokenizer.TT_WORD) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_vers_err",
				new Object[] {Integer.toString(tk.lineno())});
		}

		// Make sure it's a valid version number.

		String version = stk.sval;

		if (version.indexOf(TT_PERIOD) == -1) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_vers_mssing",
				new Object[] {Integer.toString(tk.lineno())});

		}

		try {
		    Float.valueOf(version);
		} catch (NumberFormatException ex) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_vers_err",
				new Object[] {Integer.toString(tk.lineno())});

		}

		this.version = version;

		// Check for extra stuff.

		if ((tt = stk.nextToken()) != StreamTokenizer.TT_EOF) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_vers_err",
				new Object[] {Integer.toString(tk.lineno())});
		}

		mask = VERSION_MASK;
	    } else {

		duplicate = true;
	    }
	} else if (id.equalsIgnoreCase(
				SLPTemplateRegistry.DESCRIPTION_ATTR_ID)) {

	    // Make sure there is nothing else on that line.

	    if (stk.nextToken() != StreamTokenizer.TT_EOF) {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(tk.lineno())});
	    }

	    if ((found & DESCRIPTION_MASK) == 0) {

		// Need to continue parsing help text until we reach a blank
		// line.

		String helpText = "";

		do {
		    int ptt = tt;
		    tt = tk.nextToken();

		    if (tt == StreamTokenizer.TT_WORD) {

			helpText = helpText + tk.sval + "\n";

		    } else if (tt == StreamTokenizer.TT_EOL) {

			// If previous token was end of line, quit.

			if (ptt == StreamTokenizer.TT_EOL) {

			    // Store any text first.

			    if (helpText.length() > 0) {
				description = helpText;

			    }

			    tk.pushBack();  // so same as above

			    break;
			}
		    } else if (tt == StreamTokenizer.TT_EOF) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

		    } else {

			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

		    }

		} while (true);

		mask = DESCRIPTION_MASK;
	    } else {

		duplicate = true;
	    }
	} else if (id.equalsIgnoreCase(
				SLPTemplateRegistry.SERVICE_URL_ATTR_ID)) {

	    if ((found & URL_PATH_RULES_MASK) == 0) {

		String serviceURLGrammer = "";

		// Pull everything out of the rdr StringReader until empty.

		int ic;

		while ((ic = rdr.read()) != -1) {
		    serviceURLGrammer += (char)ic;

		}

		serviceURLGrammer += "\n";

		// Need to continue parsing service URL syntax until we
		// reach a blank line.

		tt = StreamTokenizer.TT_EOL;

		do {
		    int ptt = tt;
		    tt = tk.nextToken();

		    if (tt == StreamTokenizer.TT_WORD) {

			serviceURLGrammer = serviceURLGrammer + tk.sval + "\n";

		    } else if (tt == StreamTokenizer.TT_EOL) {

			// If previous token was end of line, quit.

			if (ptt == StreamTokenizer.TT_EOL) {

			    // Store any text first.

			    if (serviceURLGrammer.length() > 0) {
				URLSyntax = serviceURLGrammer;

			    }

			    tk.pushBack();  // so same as above.

			    break;
			}
		    } else if (tt == StreamTokenizer.TT_EOF) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

		    } else {

			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

		    }

		} while (true);

		mask = URL_PATH_RULES_MASK;
	    } else {

		duplicate = true;
	    }
	} else {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_nontattribute_err",
				new Object[] {Integer.toString(tk.lineno())});

	}

	// Throw exception if a duplicate definition was detected.

	if (duplicate) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_dup_def",
				new Object[] {Integer.toString(tk.lineno())});

	}


	// Make sure the assignment ends with a blank line.

	if ((tt = tk.nextToken()) != StreamTokenizer.TT_EOL) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(tk.lineno())});

	}

	return mask;

    }


    // Parse the attributes from the tokenizer.

    private void parseAttributes(StreamTokenizer tk)
	throws ServiceLocationException {

	try {

	    do {

		// Check if at end of file yet.

		int tt = tk.nextToken();

		if (tt == StreamTokenizer.TT_EOF) {
		    break;
		}

		// If not, push token back so we can get it next time.

		tk.pushBack();

		// Parse off the attribute descriptor.

		AttributeDescriptor attDesc = parseAttribute(tk);

		// Check whether default values, if any, are correct.

		checkDefaultValues(attDesc);

		// If the attribute already exists, then throw exception.
		//  We could arguably replace existing, but it might
		//  suprise the user.

		String attrId = attDesc.getId().toLowerCase();

		if (attributeDescriptors.get(attrId) != null) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_dup_def",
				new Object[] {Integer.toString(tk.lineno())});

		}

		// Add the attribute to the descriptor table.

		attributeDescriptors.put(attrId, attDesc);

	    } while (true);

	} catch (IOException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"template_io_error",
				new Object[] {Integer.toString(tk.lineno())});
	}

    }

    // Parse a single attribute description from the tokenizer.

    private AttributeDescriptor
	parseAttribute(StreamTokenizer tk) throws ServiceLocationException {

	AttributeDescriptor attDesc = new AttributeDescriptor();
	int lineno = 0;

	try {

	    // Parse the string for attribute id, type, and flags.

	    lineno = tk.lineno();

	    int tt = tk.nextToken();

	    if (tt != StreamTokenizer.TT_WORD) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(tk.lineno())});
	    }

	    StreamTokenizer stk =
		new StreamTokenizer(new StringReader(tk.sval));

	    initIdChar(stk);

	    // Parse the attribute id.

	    parseId(stk, attDesc, lineno);

	    // Parse the type and flags.

	    parseTypeAndFlags(stk, attDesc, lineno);

	    tt = tk.nextToken();

	    if (tt == StreamTokenizer.TT_EOF) {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

	    }

	    if (tt != StreamTokenizer.TT_EOL) {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

	    }

	    // Parse initial values.

	    if (!attDesc.getIsKeyword()) {

		String tok = "";

		// Read in entire list.

		do {
		    int ptt = tt;
		    lineno = tk.lineno();
		    tt = tk.nextToken();

		    if (tt == StreamTokenizer.TT_WORD) {

			// Trim line, check for '#', indicating end of list.

			String line = tk.sval.trim();

			if (line.charAt(0) == TT_FIELD) {
			    // it's help text already.

			    if (tok.length() > 0) {
				stk =
				    new StreamTokenizer(new StringReader(tok));
				parseDefaultValues(stk, attDesc, lineno);
			    }

			    tk.pushBack();
			    break;

			} else {

			    // Otherwise concatenate onto growing list.

			    tok = tok + line;

			}

		    } else if (tt == StreamTokenizer.TT_EOL) {

			if (ptt == StreamTokenizer.TT_EOL) {
			    // end of attribute definition.

			    // Process any accumulated list.

			    if (tok.length() > 0) {
				stk =
				    new StreamTokenizer(new StringReader(tok));
				parseDefaultValues(stk, attDesc, lineno);
			    }

			    return attDesc;

			}
		    } else if (tt == StreamTokenizer.TT_EOF) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

		    } else {

			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

		    }

		} while (true);

	    } else {
		attDesc.setDefaultValues(null);
		attDesc.setAllowedValues(null);

		// Check for end of definition.

		if ((tt = tk.nextToken()) == StreamTokenizer.TT_EOL) {
		    return attDesc;

		} else if (tt == StreamTokenizer.TT_WORD) {

		    // Check for start of help text.

		    String line = tk.sval.trim();

		    if (line.charAt(0) != TT_FIELD) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(tk.lineno())});

		    } else {

			tk.pushBack();

		    }

		} else if (tt == StreamTokenizer.TT_EOF) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

		} else {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});

		}
	    }


	    // Parse help text.

	    String helpText = "";

	    do {
		int ptt = tt;
		lineno = tk.lineno();
		tt = tk.nextToken();

		if (tt == StreamTokenizer.TT_WORD) {

		    // Check for end of help text.

		    String line = tk.sval.trim();

		    if (line.charAt(0) == TT_FIELD) {

			// Help text is collected verbatim after '#'.

			helpText =
			    helpText + line.substring(1) + "\n";

		    } else {

			// We've reached the end of the help text. Store it
			//  and break out of the loop.

			if (helpText.length() > 0) {
			    attDesc.setDescription(helpText);
			}

			tk.pushBack();
			break;

		    }

		} else if (tt == StreamTokenizer.TT_EOL ||
			   tt == StreamTokenizer.TT_EOF) {

		    // If previous token was end of line, quit.

		    if (ptt == StreamTokenizer.TT_EOL) {

			// Store any text first.

			if (helpText.length() > 0) {
			    attDesc.setDescription(helpText);
			}

			// If this is a keyword attribute, set the allowed
			//  values list to null.

			if (attDesc.getIsKeyword()) {
			    attDesc.setAllowedValues(null);
			}

			return attDesc;

		    } else if (tt == StreamTokenizer.TT_EOF) {

			// Error if previous token wasn't EOL.

			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});
		    }

		} else {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});
		}

	    } while (true);

	    // Parse allowed values.

	    if (!attDesc.getIsKeyword()) {

		String tok = "";

		// Read in entire list.

		do {
		    int ptt = tt;
		    lineno = tk.lineno();
		    tt = tk.nextToken();

		    if (tt == StreamTokenizer.TT_WORD) {

			// Concatenate onto growing list.

			tok = tok + tk.sval;

		    } else if (tt == StreamTokenizer.TT_EOL) {

			if (ptt == StreamTokenizer.TT_EOL) {
			    // end of attribute definition.

			    // Process any accumulated list.

			    if (tok.length() > 0) {
				stk =
				    new StreamTokenizer(new StringReader(tok));
				parseAllowedValues(stk, attDesc, lineno);
			    }

			    return attDesc;

			}
		    } else if (tt == StreamTokenizer.TT_EOF) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_end_error",
				new Object[] {Integer.toString(tk.lineno())});

		    } else {

			throw
			    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_unk_token",
				new Object[] {Integer.toString(tk.lineno())});
		    }

		} while (true);

	    } else {

		// Error. Keyword attribute should have ended during help text
		//  parsing or before.

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(tk.lineno())});
	    }

	} catch (IOException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"template_io_error",
				new Object[] {
		    Integer.toString(tk.lineno()),
			ex.getMessage()});
	}

    }

    // Check whether the default values, if any, are correct.

    private void checkDefaultValues(AttributeDescriptor attDesc)
	throws ServiceLocationException {

	// Don't bother if it's a keyword attribute, parsing has checked.

	if (attDesc.getIsKeyword()) {
	    return;
	}

	Enumeration init = attDesc.getDefaultValues();
	Enumeration en = attDesc.getAllowedValues();
	Vector allowed = new Vector();
	String attDescType = attDesc.getValueType();

	// First, collect the allowed values.

	while (en.hasMoreElements()) {
	    Object allval = en.nextElement();

	    // Lower case strings and create opaques for comparison
	    // if type is opaque.

	    if (attDescType.equals(JAVA_STRING_TYPE)) {
		allval = ((String)allval).toLowerCase();

	    } else if (attDescType.equals(JAVA_OPAQUE_TYPE)) {
		allval = new Opaque((byte[])allval);

	    }

	    allowed.addElement(allval);
	}

	// Now compare the allowed with the initial.

	if (allowed.size() > 0) {

	    // Error if allowed is restricted but no initializers.

	    if (!init.hasMoreElements()) {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_no_init",
				new Object[] {attDesc.getId()});

	    }

	    Object val = null;

	    // Compare init values with allowed.

	    while (init.hasMoreElements()) {
		Object test = init.nextElement();
		val = test; // for exception..

		if (attDescType.equals(JAVA_STRING_TYPE)) {
		    test = ((String)test).toLowerCase();

		} else if (attDescType.equals(JAVA_OPAQUE_TYPE)) {
		    test = new Opaque((byte[])test);

		}

		if (allowed.indexOf(test) != -1) {
		    return; // found it!
		}
	    }
	    // Initializer wasn't found.

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_wrong_init",
				new Object[] {
		    val.toString(), attDesc.getId()});
	}
    }

    // Parse the attribute's id string.

    private void parseId(StreamTokenizer tk,
			 AttributeDescriptor attDesc,
			 int baseLineno)
	throws ServiceLocationException, IOException {

	// Parse the attribute's identifier tag.

	String id = parseWord(tk, baseLineno);

	int tt = tk.nextToken();

	// Parse the seperator.

	if (tt != TT_EQUALS) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {
		    Integer.toString(tk.lineno() + baseLineno)});

	}

	// Expand out any escaped ``#''. It won't be handled by
	// SLA.

	id = unescapeHash(id);

	// Expand out character escapes.

	id =
	    ServiceLocationAttribute.unescapeAttributeString(id, true);


	attDesc.setId(id);
    }

    // Parse the attribute's type and flags.

    private void
	parseTypeAndFlags(StreamTokenizer tk,
			  AttributeDescriptor attDesc,
			  int baseLineno)
	throws ServiceLocationException, IOException {

	int existingFlags = 0;

	// Parse the attribute's type.

	String type = parseWord(tk, baseLineno);

	checkAndAddType(type, attDesc, tk.lineno() + baseLineno);

	// Parse the flags.

	do {

	    // Check if any flags are left.

	    if (tk.nextToken() == StreamTokenizer.TT_EOF) {
		break;

	    } else {
		tk.pushBack();
	    }

	    int lineno = tk.lineno();

	    // Parse the flag.

	    String flag = parseWord(tk, baseLineno);

	    // Error if flags with keyword.

	    if (attDesc.getIsKeyword()) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {
			Integer.toString(tk.lineno() + baseLineno)});
	    }


	    // Check and assign it to the attribute.

	    existingFlags =
		existingFlags | checkAndAddFlag(flag,
						existingFlags,
						attDesc,
						baseLineno + lineno);

	} while (true);
    }

    // Parse the attribute's initial value(s).

    private void parseDefaultValues(StreamTokenizer tk,
				    AttributeDescriptor attDesc,
				    int baseLineno)
	throws ServiceLocationException, IOException {

	// First get the vector of initial values.

	Vector vals = parseValueList(tk, attDesc, baseLineno);

	// Check whether it works for this attribute. Type
	//  checking will be done by value list parsing.

	if (!attDesc.getIsMultivalued() && vals.size() > 1) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {
		    Integer.toString(tk.lineno() + baseLineno)});
	}

	attDesc.setDefaultValues(vals);
    }

    // Parse the attribute's allowed values.

    private void
	parseAllowedValues(StreamTokenizer tk,
			   AttributeDescriptor attDesc,
			   int baseLineno)
	throws ServiceLocationException, IOException {

	// First get the vector of all allowed values.

	Vector vals = parseValueList(tk, attDesc, baseLineno);

	// Now set the allowed value vector.

	attDesc.setAllowedValues(vals);
    }

    // Parse a value list.

    private Vector parseValueList(StreamTokenizer stk,
				  AttributeDescriptor attDesc,
				  int baseLineno)
	throws ServiceLocationException, IOException {

	Vector req = new Vector();

	// Set up the tokenizer according to the type of the
	//  attribute.

	String type = attDesc.getValueType();

	if (type.equals(JAVA_STRING_TYPE) || type.equals(JAVA_OPAQUE_TYPE)) {
	    initStringItemChar(stk);
	} else if (type.equals(JAVA_INTEGER_TYPE)) {
	    initIntItemChar(stk);
	} else if (type.equals(JAVA_BOOLEAN_TYPE)) {
	    initIdChar(stk);
	}

	// Parse through a potentially multivalued value list.

	boolean wordRequired = true;	// true when a word is required,
					// false when a comma required.
	boolean syntaxError = false;
	String reqTok = "";
	int lineno = 0;

	do {
	    int tt = stk.nextToken();
	    lineno = stk.lineno() + baseLineno;

	    if (tt ==  StreamTokenizer.TT_WORD) {

		// If a word isn't required, then the case is
		//  "token token" and is an error.

		if (!wordRequired) {
		    syntaxError = true;
		}

		reqTok = stk.sval.trim();

		// Convert the value to the proper object.

		Object reqVal = convertValue(type, reqTok, baseLineno);
		req.addElement(reqVal);

		wordRequired = false;

	    } else if (tt == StreamTokenizer.TT_EOF) {

		// If a word is required, then list ends with
		//  a comma, so error.

		if (wordRequired) {
		    syntaxError = true;
		}

		break;

	    } else if (tt == TT_COMMA) {

		// If a word is required, then error. The case is ",,".

		if (wordRequired) {
		    syntaxError = true;
		    break;
		}

		// Otherwise, the next token must be a word.

		wordRequired = true;

	    } else {

		// No other tokens are allowed.

		syntaxError = true;
		break;
	    }

	} while (true);

	if (syntaxError) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_attr_syntax",
				new Object[] {Integer.toString(lineno)});
	}

	return req;

    }

    // Check the type and add it to the attribute descriptor.

    private void checkAndAddType(String type,
				 AttributeDescriptor attDesc,
				 int lineno)
	throws ServiceLocationException {

	// Check token against recognized types.

	if (type.equalsIgnoreCase(STRING_TYPE)) {
	    attDesc.setValueType(JAVA_STRING_TYPE);

	} else if (type.equalsIgnoreCase(INTEGER_TYPE)) {
	    attDesc.setValueType(JAVA_INTEGER_TYPE);

	} else if (type.equalsIgnoreCase(BOOLEAN_TYPE)) {
	    attDesc.setValueType(JAVA_BOOLEAN_TYPE);

	} else if (type.equalsIgnoreCase(OPAQUE_TYPE)) {
	    attDesc.setValueType(JAVA_OPAQUE_TYPE);

	} else if (type.equalsIgnoreCase(KEYWORD_TYPE)) {
	    attDesc.setIsKeyword(true);

	} else {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_not_slp_type",
				new Object[] {Integer.toString(lineno)});
	}

    }

    // Check the flag and add it to the attribute descriptor.

    private int checkAndAddFlag(String flag,
				int matched,
				AttributeDescriptor attDesc,
				int lineno)
	throws ServiceLocationException {

	boolean duplicate = false;

	// We depend on the attribute descriptor being initialized to
	// nothing, i.e. false for all flags and for keyword.

	if (flag.equalsIgnoreCase(MULTIPLE_FLAG)) {

	    if ((matched & MULTIPLE_MASK) != 0) {
		duplicate = true;

	    } else {

		// Check for boolean. Booleans may not have
		// multiple values.

		if (attDesc.getValueType().equals(JAVA_BOOLEAN_TYPE)) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_boolean_multi",
				new Object[] {Integer.toString(lineno)});
		}

		attDesc.setIsMultivalued(true);
		return MULTIPLE_MASK;

	    }

	} else if (flag.equalsIgnoreCase(LITERAL_FLAG)) {

	    if ((matched & LITERAL_MASK) != 0) {
		duplicate = true;

	    } else {
		attDesc.setIsLiteral(true);
		return LITERAL_MASK;
	    }

	} else if (flag.equalsIgnoreCase(EXPLICIT_FLAG)) {

	    if ((matched & EXPLICIT_MASK) != 0) {
		duplicate = true;

	    } else {
		attDesc.setRequiresExplicitMatch(true);
		return EXPLICIT_MASK;
	    }

	} else if (flag.equalsIgnoreCase(OPTIONAL_FLAG)) {

	    if ((matched & OPTIONAL_MASK) != 0) {
		duplicate = true;

	    } else {
		attDesc.setIsOptional(true);
		return OPTIONAL_MASK;
	    }

	} else {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_invalid_attr_flag",
				new Object[] {Integer.toString(lineno)});
	}


	if (duplicate) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_dup_attr_flag",
				new Object[] {Integer.toString(lineno)});
	}

	return 0; // never happens.
    }

    // Parse a word out of the tokenizer. The exact characters
    //  will depend on what the syntax tables have been set to.

    private String parseWord(StreamTokenizer tk, int baseLineno)
	throws ServiceLocationException, IOException {

	int tt = tk.nextToken();

	if (tt == StreamTokenizer.TT_WORD) {
	    return (tk.sval);

	} else {

	    String errorToken = "";

	    // Report the erroneous characters.

	    if (tt == StreamTokenizer.TT_NUMBER) {
		errorToken = Double.toString(tk.nval);
	    } else if (tt == StreamTokenizer.TT_EOL) {
		errorToken = "<end of line>";
	    } else if (tt == StreamTokenizer.TT_EOF) {
		errorToken = "<end of file>";
	    } else {
		errorToken = (Character.valueOf((char)tt)).toString();
	    }

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_invalid_tok",
				new Object[] {
		    Integer.toString(tk.lineno() + baseLineno)});

	}

    }

    // Convert a value list token to the value.

    private Object convertValue(String type,
				String reqTok,
				int lineno)
	throws ServiceLocationException,
	       IOException {

	Object reqVal = null;

	if (type.equals(JAVA_STRING_TYPE)) {

	    // Expand out any escaped ``#''. It won't be handled by
	    //  SLA.

	    reqTok = unescapeHash(reqTok);

	    // Expand out character escapes.

	    reqVal =
		ServiceLocationAttribute.unescapeAttributeString(reqTok,
								 false);

	} else if (type.equals(JAVA_INTEGER_TYPE)) {

	    try {

		reqVal = Integer.valueOf(reqTok);

	    } catch (NumberFormatException ex) {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_expect_int",
				new Object[] {
			Integer.toString(lineno), reqTok });
	    }
	} else if (type.equals(JAVA_BOOLEAN_TYPE)) {

	    // Boolean.valueOf() doesn't handle this properly.

	    if (reqTok.equalsIgnoreCase(TRUE_TOKEN)) {

		reqVal = Boolean.valueOf(true);

	    } else if (reqTok.equalsIgnoreCase(FALSE_TOKEN)) {

		reqVal = Boolean.valueOf(false);

	    } else {

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"template_expect_bool",
				new Object[] {
			Integer.toString(lineno), reqTok});
	    }
	} else if (type.equals(JAVA_OPAQUE_TYPE)) {

	    reqVal = Opaque.unescapeByteArray(reqTok);

	} else {

	    Assert.slpassert(false,
			  "template_attr_desc",
			  new Object[0]);
	}

	return reqVal;
    }

    // Expand out any escaped hashes. Not handled by SLA.

    private String unescapeHash(String str) {

	StringBuffer buf = new StringBuffer();
	int len = ESC_HASH.length();
	int i, j = 0;

	for (i = str.indexOf(ESC_HASH, j);
	    i != -1;
	    i = str.indexOf(ESC_HASH, j)) {

	    buf.append(str.substring(j, i));
	    buf.append(HASH);
	    j = i + len;
	}

	len = str.length();

	if (j < len) {
	    buf.append(str.substring(j, len));

	}

	return buf.toString();
    }

}
