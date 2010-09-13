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

public class IncludeOptionValue extends OptionValue {
    private String value;
    private boolean valid;

    // Serialization id for this class
    static final long serialVersionUID = -1764994428959712447L;
    
    protected IncludeOptionValue() {
	value = "";
	valid = false;
    }
    
    public void setValue(Object value) throws ValidationException {
	if (value instanceof String) {
	    if (((String)value).length() == 0) {
		// Empty values are not acceptable
		throwException("invalid_include_option", null);
	    }
	    this.value = (String)value;
	    valid = true;
	} else {
	    setValue(value.toString());
	}
    }
    
    public String getName() {
	return "Include";
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
	IncludeOptionValue v = new IncludeOptionValue();
	v.value = value;
	v.valid = valid;
	return v;
    }
}
