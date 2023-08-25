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

//  AttributeDescriptor.java: Describes an SLP attribute.
//  Author:           James Kempf
//  Created On:       Thu Jun 19 10:38:01 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Jun  2 13:29:08 1998
//  Update Count:     29
//

package com.sun.slp;

import java.util.*;


/**
 * The instances of the AttributeDescriptor class
 * return information on a particular service location attribute. This
 * information is primarily for GUI tools. Programmatic attribute
 * verification should be done through the ServiceLocationAttributeVerifier.
 *
 * @author James Kempf
 *
 */

class AttributeDescriptor
    extends Object
    implements ServiceLocationAttributeDescriptor {

    // Indicates byte array type.

    private static final String JAVA_OPAQUE_TYPE = "[B";

    private String id = "";
    private String valueType = "";
    private String description = "";
    private Vector allowedValues = new Vector();
    private Vector defaultValues = new Vector();
    private boolean isMultivalued = false;
    private boolean isOptional = false;
    private boolean requiresExplicitMatch = false;
    private boolean isLiteral = false;
    private boolean isKeyword = false;

    /**
     * Return the attribute's id.
     *
     * @return A String with the attribute's id.
     */

    final public String getId() {
	return id;
    }

    /**
     * Return the fully qualified Java type of the attribute. SLP types
     * are translated into Java types as follows:
     *
     *	STRING		java.lang.String
     *	INTEGER		java.lang.Integer
     *	BOOLEAN		java.lang.Boolean
     *	OPAQUE		[B (i.e. array of byte, byte[]);
     *	KEYWORD		null string, ""
     *
     * @return A String containing the Java type name for the attribute values.
     */

    final public String getValueType() {
	return valueType;
    }

    /**
     * Return attribute's help text.
     *
     * @return A String containing the attribute's help text.
     */

    final public String getDescription() {
	return description;
    }

    /**
     * Return an Enumeration of allowed values for the attribute type.
     * For keyword attributes returns null. For no allowed values
     * (i.e. unrestricted) returns an empty Enumeration. Small memory
     * implementations may want to parse values on demand rather
     * than at the time the descriptor is created.
     *
     * @return An Enumeration of allowed values for the attribute or
     *         null if the attribute is keyword.
     */

    final public Enumeration getAllowedValues() {

	if (getIsKeyword()) {
	    return null;
	} else {
	    return allowedValues.elements();
	}
    }


    /**
     * Return an Enumeration of default values for the attribute type.
     * For keyword attributes returns null. For no allowed values
     * (i.e. unrestricted) returns an empty Enumeration. Small memory
     * implementations may want to parse values on demand rather
     * than at the time the descriptor is created.
     *
     * @return An Enumeration of default values for the attribute or
     *	      null if the attribute is keyword.
     */

    final public Enumeration getDefaultValues() {

	if (getIsKeyword()) {
	    return null;
	} else {
	    return defaultValues.elements();
	}
    }

    /**
     * Returns true if the "M" flag is set.
     *
     * @return True if the "M" flag is set.
     */

    final public boolean getIsMultivalued() {
	return isMultivalued;
    }

    /**
     * Returns true if the "O" flag is set.
     *
     * @return True if the "O" flag is set.
     */

    final public boolean getIsOptional() {
	return isOptional;
    }

    /**
     * Returns true if the "X" flag is set.
     *
     * @return True if the "X" flag is set.
     */

    final public boolean getRequiresExplicitMatch() {
	return requiresExplicitMatch;
    }

    /**
     * Returns true if the "L" flag is set.
     *
     * @return True if the "L" flag is set.
     */

    final public boolean getIsLiteral() {
	return isLiteral;
    }

    /**
     * Returns true if the attribute is a keyword attribute.
     *
     * @return True if the attribute is a keyword attribute
     */

    final public boolean getIsKeyword() {
	return isKeyword;
    }

    //
    // Package private interface for setting properties.
    //

    /**
     * Set the attribute's id.
     *
     * @param nid New id string
     */

    void setId(String nid) {
	id = nid;
    }

    /**
     * Set the fully qualified Java type of the attribute. We don't check
     * the argument here, assuming that the caller has taken care of it.
     *
     * @param nvt New value type.
     */

    void setValueType(String nvt) {
	valueType = nvt;
    }

    /**
     * Set attribute's help text.
     *
     * @param ndes A String containing the attribute's help text.
     */

    void setDescription(String ndes) {
	description = ndes;
    }

    /**
     * Set the allowed values for an attribute.
     *
     * @param nnv A vector of allowed values for the attribute.
     */

    void setAllowedValues(Vector nnv) {
	allowedValues = nnv;
    }


    /**
     * Set the default values for an attribute.
     *
     * @param nnv A vector of default values for the attribute.
     */

    void setDefaultValues(Vector nnv) {
	defaultValues = nnv;
    }

    /**
     * Set the isMultivalued flag.
     *
     * @param flag New multivalued flag.
     */

    void setIsMultivalued(boolean flag) {
	isMultivalued = flag;
    }

    /**
     * Set the isOptional flag.
     *
     * @param flag New optional flag.
     */

    void setIsOptional(boolean flag) {
	isOptional = flag;
    }

    /**
     * Set the requiresExplicitMatch flag.
     *
     * @param flag New explicit match flag.
     */

    void setRequiresExplicitMatch(boolean flag) {
	requiresExplicitMatch = flag;
    }

    /**
     * Set the isLiteral flag.
     *
     * @param flag New literal flag.
     */

    void setIsLiteral(boolean flag) {
	isLiteral = flag;
    }

    /**
     * Set the keyword attribute flag.
     *
     * @param flag New keyword attribute flag.
     */

    void setIsKeyword(boolean flag) {
	isKeyword = flag;
    }

    /**
     * Format a string with the id and all the fields.
     *
     */

    public String toString() {

	String ret = "";

	ret += "\nid:" + id + "\n";
	ret += "valueType:" + valueType + "\n";
	ret += "description:" + description + "\n";
	ret +=
	    "defaultValues:" +
	    (defaultValues == null ? "<null>":
	    (valueType.equals(JAVA_OPAQUE_TYPE) ?
	    formatByteArrays(defaultValues) : defaultValues.toString())) +
	    "\n";
	ret +=
	    "allowedValues:" +
	    (allowedValues == null ? "<null>":
	    (valueType.equals(JAVA_OPAQUE_TYPE) ?
	    formatByteArrays(allowedValues) : allowedValues.toString())) +
	    "\n";
	ret += "isMultivalued:" + (isMultivalued ? "true":"false") + "\n";
	ret += "isOptional:" + (isOptional ? "true":"false") + "\n";
	ret += "requiresExplicitMatch:" +
	    (requiresExplicitMatch ? "true":"false") + "\n";
	ret += "isLiteral:" + (isLiteral ? "true":"false") + "\n";
	ret += "isKeyword:" + (isKeyword ? "true":"false") + "\n\n";

	return ret;
    }

    // Formats an array of bytes for opaque, rather than just the address.

    private String formatByteArrays(Vector arrays) {
	int i, n = arrays.size();
	StringBuffer ret = new StringBuffer();

	ret.append("[");

	for (i = 0; i < n; i++) {
	    byte array[] = (byte[])arrays.elementAt(i);

	    ret.append("{ ");

	    int j, m = array.length;

	    for (j = 0; j < m; j++) {
		ret.append("0x");
		ret.append(Integer.toHexString((int)array[j]&0xFF));
		ret.append(j == m - 1 ? " } " : ",");
	    }

	    ret.append(i == n - 1 ? "":" , ");
	}

	ret.append("]");

	return ret.toString();
    }

}
