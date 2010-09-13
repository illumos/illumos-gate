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

import java.io.Serializable;
import java.util.*;
import java.math.BigInteger;

/**
 * This class provides a way to retain the radix specified by the user
 * when entering the data.  Currently only support 10 and 16 for radix.
 */
class NumberValue implements Serializable {
    private Number value;
    private int radix;

    // Serialization id for this class
    static final long serialVersionUID = -3480903816949402385L;

    public NumberValue(Number value, int radix) {
    	this.value = value;
	this.radix = radix;
    }

    public String toString() {
	if (value instanceof BigInteger) {
	    return ((BigInteger)value).toString(radix);
	}
	// Handle hex specially
	if (radix == 16) {
	    return "0x" + Long.toHexString(value.longValue());
	} else {
	    return Long.toString(value.longValue());
	}
    }
}

public class NumberOptionValue extends OptionValue {
    private String name;
    private Vector nums;
    private boolean valid;
    private int radix;

    // Serialization id for this class
    static final long serialVersionUID = -5824132577553748971L;

    protected NumberOptionValue(String name) {
	this.name = name;
	nums = null;
	valid = false;
    }
    
    public void setValue(Object value) throws ValidationException {
	// Find option in option definition table in order to validate the data
	Option option = OptionsTable.getTable().get(name);
	if (option == null) {
	    Object [] args = { name };
	    throwException("invalid_option", args);
	}

	// The granularity attribute must be interpreted in context
	// of what kind of number option we're dealing with. If this
	// is a NUMBER option, then granularity defines the number of
	// octets the number will contain (in other words the size).
	// For all other number types it defines how many numbers of
	// that type make make a valid option of that type. Note that
	// in the case of NUMBER options that granularity always defaults
	// to one. XXX Swill code here. Should probably define a new class and
	// create an array of them and simply loop.
	byte type = option.getType();
	boolean isUnsigned = false;
	int bits = option.getGranularity() * 8;
	int realGranularity = option.getGranularity();

	if (type == Option.types[Option.NUMBER].getCode()) {
	    realGranularity = 1;
	} else if (type == Option.types[Option.SNUMBER8].getCode()) {
	    bits = 7;
	} else if (type == Option.types[Option.UNUMBER8].getCode()) {
	    bits = 8;
	    isUnsigned = true;
	} else if (type == Option.types[Option.SNUMBER16].getCode()) {
	    bits = 15;
	} else if (type == Option.types[Option.UNUMBER16].getCode()) {
	    bits = 16;
	    isUnsigned = true;
	} else if (type == Option.types[Option.SNUMBER32].getCode()) {
	    bits = 31;
	} else if (type == Option.types[Option.UNUMBER32].getCode()) {
	    bits = 32;
	    isUnsigned = true;
	} else if (type == Option.types[Option.SNUMBER64].getCode()) {
	    bits = 63;
	} else if (type == Option.types[Option.UNUMBER64].getCode()) {
	    bits = 64;
	    isUnsigned = true;
	}

	Vector newNums = new Vector();
	if (value instanceof String) {
	    if (((String)value).length() == 0) {
		// Empty strings are not acceptable
		Object [] args = { name,
		    Option.getTypeDhcptabString(type) };
		throwException("invalid_option_value", args);
	    }
	    // Parse each token into an object of the correct numeric type
	    StringTokenizer st = new StringTokenizer((String)value, " ");
	    while (st.hasMoreTokens()) {
		int radix = 10;
		String s = st.nextToken();
		if (s.startsWith("0x") || s.startsWith("0X")) {
		    radix = 16;
		    s = s.substring(2);
		} else if (s.startsWith("0") && (s.length() > 1)) {
		    radix = 8;
		    s = s.substring(1);
		}

		BigInteger b;
		try {
		    b = new BigInteger(s, radix);
		    if (b.bitLength() > bits) {
			Object [] args = { name,
			    Option.getTypeDhcptabString(type) };
			throwException("invalid_option_value", args);
		    }
		    if (isUnsigned && b.compareTo(BigInteger.ZERO) < 0) {
			Object [] args = { name,
			    Option.getTypeDhcptabString(type) };
			throwException("invalid_option_value", args);
		    }
		    newNums.addElement(new NumberValue(b, radix));
		} catch (NumberFormatException e) {
			Object [] args = { name,
			    Option.getTypeDhcptabString(type) };
			throwException("invalid_option_value", args);
		}
	    }
	} else if (value instanceof Number) {
	    newNums.addElement(new NumberValue((Number)value, 10));
	} else if (!(value instanceof Vector)) {
	    Object [] args = { name,
		Option.getTypeDhcptabString(type) };
	    throwException("invalid_option_value", args);
	} else {
	    // Caller supplied a vector; make sure each value is a number
	    Enumeration en = ((Vector)value).elements();
	    while (en.hasMoreElements()) {
	        Object o = en.nextElement();
		if (!(o instanceof Number)) {
		    Object [] args = { name,
			Option.getTypeDhcptabString(type) };
		    throwException("invalid_option_value", args);
		} else {
		    newNums.addElement(new NumberValue((Number)o, 10));
	        }
	    }
	}
	
	// We now have a vector of numbers; check count against expected
	if (newNums.size() % realGranularity != 0) {
	    Object [] args = { name, Integer.toString(realGranularity) };
	    throwException("invalid_option_granularity", args);
	}
	if ((option.getMaximum() != 0)
		&& (newNums.size() / realGranularity > option.getMaximum())) {
	    Object [] args = { name, Integer.toString(option.getMaximum()) };
	    throwException("invalid_option_maximum", args);
	}

	nums = newNums;
	valid = true;
    }
    
    public String getName() {
	return name;
    }
    
    public String getValue() {
	if (nums == null || nums.size() == 0) {
	    return "";
	}
	StringBuffer buf = new StringBuffer();
	for (Enumeration en = nums.elements(); en.hasMoreElements(); ) {
	    if (buf.length() != 0) {
		buf.append(' ');
	    }
	    buf.append(en.nextElement().toString());
	}
	return buf.toString();
    }
    
    public String toString() {
	return (getName() + "=" + getValue());
    }

    public boolean isValid() {
	return valid;
    }
    
    public Object clone() {
	NumberOptionValue v = new NumberOptionValue(name);
	if (nums != null) {
	    v.nums = (Vector)nums.clone();
	}
	v.valid = valid;
	return v;
    }
}
