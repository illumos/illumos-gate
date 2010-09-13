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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.data;

import java.util.Vector;
import java.util.Enumeration;

public class AsciiOptionValue extends OptionValue {
    private String name;
    private String value;
    private boolean valid;

    // Serialization id for this class
    static final long serialVersionUID = -4937655446360683504L;
    
    protected AsciiOptionValue(String name) {
	this.name = name;
	value = null;
	valid = false;
    }
    
    public String getName() {
	return name;
    }
    
    public String getValue() {
    	// Before we return the value, we go through and escape special chars.
	StringBuffer retValue = new StringBuffer();
	char [] c = value.toCharArray();
	for (int i = 0; i < c.length; ++i) {
	    if (c[i] == '\\' || c[i] == '"') {
	        retValue.append('\\');
	    }
	    retValue.append(c[i]);
	}
	return retValue.toString();
    }
    
    public void setValue(Object value) throws ValidationException {
	// Find option in option definition table in order to validate the data
	Option option = OptionsTable.getTable().get(name);
	if (option == null) {
	    Object [] args = { name };
	    throwException("invalid_option", args);
	}
	if (value instanceof String) {
	    String newValue = (String)value;
	    // Either quoted, or not, but must balance
	    if (newValue.startsWith("\"") ^ newValue.endsWith("\"")) { 
		Object [] args = { name,
		    Option.getTypeDhcptabString(option.getType()) };
		throwException("invalid_option_value", args);
	    }
	    if (newValue.startsWith("\"")) {
		newValue = newValue.substring(1, newValue.length() - 1);
	    }
	    if (newValue.length() == 0) {
		// Empty strings are not acceptable
		Object [] args = { name,
		    Option.getTypeDhcptabString(option.getType()) };
		throwException("invalid_option_value", args);
	    }
	    // Check that the resulting length is OK
	    if ((option.getMaximum() != 0)
		    && (newValue.length() > option.getMaximum())) {
		Object [] args = { name,
		    Integer.toString(option.getMaximum()) };
		throwException("invalid_option_maximum", args);
	    }
	    this.value = newValue;
	    valid = true;
	} else if (value instanceof Vector) {
	    /*
	     * We generate the value by creating a blank-separated list of
	     * tokens; each token is the product of a toString() on the
	     * vector's elements.
	     */
	    StringBuffer b = new StringBuffer();
	    Enumeration en = ((Vector)value).elements();
	    while (en.hasMoreElements()) {
		if (b.length() != 0) {
		    b.append(' ');
		}
		b.append(en.nextElement().toString());
	    }
	    setValue(b.toString());
	} else {
	    // Anything else should just tell us what it looks like as a string.
	    setValue(value.toString());
	}
    }
    
    public String toString() {
	return (getName() + "=\"" + getValue() + "\"");
    }
    
    public boolean isValid() {
	return valid;
    }
    
    public Object clone() {
	AsciiOptionValue v = new AsciiOptionValue(name);
	v.value = value;
	v.valid = valid;
	return v;
    }
}
