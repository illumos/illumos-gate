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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.common;

import java.lang.IllegalArgumentException;
import java.util.ArrayList;
import java.text.MessageFormat;

/**
 * This class is used to represent all the command line options.
 */
public class DhcpCliOptions {

    /**
     * Actual container for the options.
     */
    ArrayList options;

    /**
     * Basic constructor.
     */
    public DhcpCliOptions() {

	options = new ArrayList();

    } // constructor

    /**
     * Creates a new option and adds it to the list.
     * @param flag the option key value
     * @param value the option value
     */
    public void setOption(int flag, String value)
	throws IllegalArgumentException {

	DhcpCliOption option = new DhcpCliOption(flag, value);
	int i = options.indexOf(option);
	if (i == -1) {
	    options.add(option);
	} else {
	    String format =
		ResourceStrings.getString("repeated_option");
	    Object[] args = new Object[1];
	    args[0] = option.getOptionCharacter();
	    String msg = MessageFormat.format(format, args);
	    throw new IllegalArgumentException(msg);
	}

    } // setOption

    /**
     * Reports as to whether or not an option exists in the list.
     * @param flag the option key value
     * @return true if the option is in the list, false if not
     */
    public boolean isSet(int flag) {

	DhcpCliOption option = new DhcpCliOption(flag);
	return options.contains(option);

    } // isSet

    /**
     * Returns the value of an option.
     * @param flag the option key value
     * @return the value of the option or null if the option is not
     * in the list.
     */
    public String valueOf(int flag) {

	DhcpCliOption option = new DhcpCliOption(flag);

	int i = options.indexOf(option);
	if (i != -1) {
	    return ((DhcpCliOption)options.get(i)).getValue();
	} else {
	    return null;
	}
    } // valueOf

    /**
     * Given a list of supported options, validates that there are no
     * options in the in the option list that are not supported.
     * @param supportedOptions array of option key values
     * @return true if there are no options in the option list that are
     * not in the supportedOptions, false otherwise.
     */
    public void validate(int [] supportedOptions)
	throws IllegalArgumentException {

	boolean result = true;
	int option = 0;

	for (int i = 0; i < options.size() && result; i++) {
	    option = ((DhcpCliOption)options.get(i)).getOption();
	    result = false;
	    for (int j = 0; j < supportedOptions.length && !result; j++) {
		if (supportedOptions[j] == option) {
		    result = true;
		}
	    }
	}

	if (!result) {
	    String format =
		ResourceStrings.getString("bad_function_option");
	    Object[] args = new Object[1];
	    args[0] = DhcpCliOption.getOptionCharacter(option);
	    String msg = MessageFormat.format(format, args);
	    throw new IllegalArgumentException(msg);
	}

    } // validate

} // DhcpCliOptions
