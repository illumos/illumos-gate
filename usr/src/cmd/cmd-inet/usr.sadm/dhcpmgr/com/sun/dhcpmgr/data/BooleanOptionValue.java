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

public class BooleanOptionValue extends OptionValue {
    private String name;

    // Serialization id for this class
    static final long serialVersionUID = 5379063769810230706L;
    
    protected BooleanOptionValue(String name) {
	this.name = name;
    }
    
    public String getName() {
	return name;
    }
    
    public String getValue() {
	return "";
    }
    
    public void setValue(Object value) throws ValidationException {
	// Booleans must have an empty value
	Option option = OptionsTable.getTable().get(name);
	if (value != null && value.toString().length() != 0) {
	    Object [] args = { name,
		Option.getTypeDhcptabString(option.getType()) };
	    throwException("invalid_option_value", args);
	}
    }
    
    public String toString() {
	return getName();
    }
    
    public boolean isValid() {
	return true;
    }
    
    public Object clone() {
	return new BooleanOptionValue(name);
    }
}
