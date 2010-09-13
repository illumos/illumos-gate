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

import java.util.*;
import java.io.Serializable;

/**
 * This class provides a global table of all the options currently known.
 * It is implemented as a singleton as there should be no need for more
 * than a single instance of this table.  It includes both the standard
 * options and any vendor or site options defined in the current environment.
 */
public class OptionsTable implements Serializable {
    private Hashtable options;
    private static OptionsTable table = null;
    
    protected OptionsTable() {
	// Get the standard options we know about
	StandardOptions stdopts = new StandardOptions();

	// Initialize hash table with extra size we will probably need.
	options = new Hashtable(stdopts.size() + 20);

	// Add the standard options to the table
	add(stdopts.getAllOptions());
    }
    
    /**
     * Add an array of options to the table.
     * @param opts An array of Options
     */
    public void add(Option [] opts) {
	for (int i = 0; opts != null && i < opts.length; ++i) {
	    add(opts[i]);
	}
    }
    
    /**
     * Add a single option to the table.
     * @param o The option to add.
     */
    public void add(Option o) {
	// Don't add unless it is a valid option.
	if (o.isValid()) {
	    options.put(o.getKey(), o);
	}
    }
    
    /**
     * Retrieve an option from the table by name
     * @param opt the name of the option to retrieve
     * @return the option found, or null if the option is not in the table
     */
    public Option get(String opt) {
	return (Option)options.get(opt);
    }
    
    /**
     * Retrieve an option from the table by its code
     * @param code the code of the option to retrieve
     * @return the option found, or null if the option is not in the table
     */
    public Option getByCode(short code) {

	Option option = null;
	for (Enumeration e = elements(); e.hasMoreElements(); ) {
	    if (((Option)e.nextElement()).getCode() == code) {
		option = (Option)e.nextElement();
	    }
	}
	return (option);
    }
    
    /**
     * Enumerate the options in this table for those that might need to walk it.
     * @return an Enumeration of the options
     */
    public Enumeration elements() {
	return options.elements();
    }
    
    /**
     * Return the global table, create it if not already in existence.
     * @return the current options table
     */
    public static OptionsTable getTable() {
	if (table == null) {
	    table = new OptionsTable();
	}
	return table;
    }
}
