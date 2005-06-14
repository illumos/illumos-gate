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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.data;

import java.util.Vector;
import java.util.Enumeration;

public class OctetOptionValue extends OptionValue {
    private String name;
    private String value;
    private boolean valid;

    // Serialization id for this class
    static final long serialVersionUID = -3267221437949696358L;
    
    protected OctetOptionValue(String name) {
	this.name = name;
	value = "";
	valid = false;
    }
    
    public void setValue(Object value) throws ValidationException {
	// Find option in option definition table in order to validate the data
	Option option = OptionsTable.getTable().get(name);
	if (option == null) {
		Object [] args = { name };
		throwException("invalid_option", args);
	}
	if (value instanceof String) {
	    if (((String)value).length() == 0) {
		// Empty values are not acceptable
		Object [] args = { name,
		    Option.getTypeDhcptabString(option.getType()) };
		throwException("invalid_option_value", args);
	    }
	    // Just make a copy of the reference
	    this.value = (String)value;
	    valid = true;
	} else if (value instanceof Vector) {
	    /*
	     * Generate the value by concatenating toString()'s on the
	     * vector's elements
	     */
	    StringBuffer b = new StringBuffer();
	    Enumeration en = ((Vector)value).elements();
	    while (en.hasMoreElements()) {
		b.append(en.nextElement().toString());
	    }
	    setValue(b.toString());
	} else {
	    // Convert anything else to a string
	    setValue(value.toString());
	}
    }

    public String getName() {
	return name;
    }
    
    public String getValue() {
	return value;
    }
    
    public String toString() {
	return (getName() + "=" + getValue());
    }

    public boolean isValid() {
	return valid;
    }
    
    public Object clone() {
	OctetOptionValue v = new OctetOptionValue(name);
	v.value = value;
	v.valid = valid;
	return v;
    }
}
