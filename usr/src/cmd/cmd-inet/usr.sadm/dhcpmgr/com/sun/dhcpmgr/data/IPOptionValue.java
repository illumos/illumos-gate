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

import java.net.*;
import java.util.*;

public class IPOptionValue extends OptionValue {
    private String name;
    private Vector addrs;
    private boolean valid;
    
    // Serialization id for this class
    static final long serialVersionUID = -7894568061270794048L;

    protected IPOptionValue(String name) {
	this.name = name;
	addrs = null;
	valid = false;
    }
    
    public void setValue(Object value) throws ValidationException {
	// Find option in option definition table in order to validate the data
	Option option = OptionsTable.getTable().get(name);
	if (option == null) {
	    Object [] args = { name };
	    throwException("invalid_option", args);
	}
	Vector newAddrs = new Vector();
	if (value instanceof String) {	
	    if (((String)value).length() == 0) {
		// Empty strings aren't acceptable
		Object [] args = { name,
		    Option.getTypeDhcptabString(option.getType()) };
		throwException("invalid_option_value", args);
	    }    
	    /*
	     * Break string apart at whitespace and use it to construct
	     * a vector of IPAddresses
	     */
	    StringTokenizer st = new StringTokenizer((String)value, " ");
	    while (st.hasMoreTokens()) {
		newAddrs.addElement(new IPAddress(st.nextToken()));
	    }
	} else if (value instanceof InetAddress) {
	    newAddrs.addElement(value);
	} else if (value instanceof IPAddress) {
	    newAddrs.addElement(value);
	} else if (!(value instanceof Vector)) {
	    // Can't handle anything else but a vector of addresses
	    Object [] args = { name,
		Option.getTypeDhcptabString(option.getType()) };
	    throwException("invalid_option_value", args);
	} else {
	    // Make sure vector only contains InetAddresses or IPAddresses
	    newAddrs = (Vector)value;
	    for (Enumeration en = newAddrs.elements(); en.hasMoreElements(); ) {
		Object o = en.nextElement();
		if (!(o instanceof InetAddress) && !(o instanceof IPAddress)) {
		    Object [] args = { name,
			Option.getTypeDhcptabString(option.getType()) };
		    throwException("invalid_option_value", args);
		}
	    }
	}
	if ((newAddrs.size() % option.getGranularity()) != 0) {
	    Object [] args = { name,
		Integer.toString(option.getGranularity()) };
	    throwException("invalid_option_granularity", args);
	}
	if ((option.getMaximum() != 0) &&
	    (newAddrs.size() / option.getGranularity()) >
		option.getMaximum()) {
	    Object [] args = { name, Integer.toString(option.getMaximum()) };
	    throwException("invalid_option_maximum", args);
	}
	
	addrs = newAddrs;
	valid = true;
    }
    
    public String getName() {
	return name;
    }
    
    public String getValue() {
	if (addrs == null || addrs.size() == 0) {
	    return "";
	}
	StringBuffer buf = new StringBuffer();
	for (Enumeration en = addrs.elements(); en.hasMoreElements(); ) {
	    Object o = en.nextElement();
	    if (buf.length() != 0) {
		buf.append(' ');
	    }
	    if (o instanceof IPAddress) {
		buf.append(((IPAddress)o).getHostAddress());
	    } else {
		buf.append(((InetAddress)o).getHostAddress());
	    }
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
	IPOptionValue v = new IPOptionValue(name);
	if (addrs != null) {
		v.addrs = (Vector)addrs.clone();
	}
	v.valid = valid;
	return v;
    }
}
