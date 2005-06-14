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

/**
 * This class provides a way for us to handle errors in the dhcptab which
 * may have been introduced through the command line or direct editing of
 * the table.  The idea is for the OptionValueFactory to trap bad option
 * names or values and store them in an instance of this class so that the
 * user can then be told about the error and allowed to fix it.
 */
public class BogusOptionValue extends OptionValue {
    private String name;
    private String value;

    // Serialization id for this class
    static final long serialVersionUID = 8573418100554161901L;

    protected BogusOptionValue(String name) {
	this.name = name;
	value = null;
    }
    
    protected BogusOptionValue(String name, Object value) {
    	this.name = name;
	setValue(value);
    }

    public String getName() {
	return name;
    }
    
    public String getValue() {
	return value;
    }
    
    public void setValue(Object value) {
	if (value instanceof Vector) {
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
	} else if (value instanceof String) {
	    this.value = (String)value;
	} else {
	    // Anything else should just tell us what it looks like as a string.
	    setValue(value.toString());
	}
    }
    
    public String toString() {
	return (getName() + "=\"" + getValue() + "\"");
    }
    
    public boolean isValid() {
	// This kind of option is never valid
	return false;
    }
    
    public Object clone() {
	return new BogusOptionValue(name, value);
    }
}
