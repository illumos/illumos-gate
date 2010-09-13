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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.data;

import java.util.Vector;

/**
 * This class provides the functionality to construct an option value of the
 * correct type when only the tag we associate with the option value is known.
 */
public class OptionValueFactory {
    private static OptionsTable optionsTable = OptionsTable.getTable();

    /**
     * Construct an option value given the name, and initialize it to the
     * provided value.
     * @param name the name of the option
     * @param value the initial value for the option
     * @return an OptionValue of the correct type for this option.  If the name
     * or value supplied is invalid in some way, an instance of
     * BogusOptionValue is returned and the caller should take appropriate
     * action.
     */
    public static OptionValue newOptionValue(String name, Object value) {
	OptionValue v;
	try {
	    v = newOptionValue(name);
	    v.setValue(value);
	} catch (ValidationException e) {
	    // Not a valid value; put it in the bogus value placeholder
	    v = new BogusOptionValue(name, value);
	}
	return v;
    }
    
    /**
     * Construct an empty option value given the name
     * @param name the name of the option
     * @return an OptionValue of the correct type for this option.
     */
    public static OptionValue newOptionValue(String name) {
	if (name.length() == 0) {
	    // Empty name is not acceptable
	    return new BogusOptionValue(name);
	}
	Option opt = optionsTable.get(name);
	if (opt == null) {
	    // Include is not in the options table
	    if (name.equals("Include")) {
		return new IncludeOptionValue();
	    } else {
	    	/*
		 * Bogus option name; create a bogus value that callers
		 * can pick up later.
		 */
		 return new BogusOptionValue(name);
	    }
	}

	byte type = opt.getType();
	if (type == Option.types[Option.ASCII].getCode()) {
	    return new AsciiOptionValue(name);
	} else if (type == Option.types[Option.BOOLEAN].getCode()) {
	    return new BooleanOptionValue(name);
	} else if (type == Option.types[Option.IP].getCode()) {
	    return new IPOptionValue(name);
	} else if (type == Option.types[Option.OCTET].getCode()) {
	    return new OctetOptionValue(name);
	} else if (type == Option.types[Option.NUMBER].getCode() ||
	    type == Option.types[Option.UNUMBER8].getCode() ||
	    type == Option.types[Option.UNUMBER16].getCode() ||
	    type == Option.types[Option.UNUMBER32].getCode() ||
	    type == Option.types[Option.UNUMBER64].getCode() ||
	    type == Option.types[Option.SNUMBER8].getCode() ||
	    type == Option.types[Option.SNUMBER16].getCode() ||
	    type == Option.types[Option.SNUMBER32].getCode() ||
	    type == Option.types[Option.SNUMBER64].getCode()) {
	    return new NumberOptionValue(name);
	} else {
	    // This should never happen
	    return new BogusOptionValue(name);
	}
    }
}
