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
package com.sun.dhcpmgr.cli.common;

import java.lang.IllegalArgumentException;
import java.text.MessageFormat;

/**
 * This class provides the functionality for parsing command line
 * arguments (similar to getsubopt(3C)).
 * <br>
 * After constructing an instance of it, getNextSubOption() can be used
 * to get the next suboption. getSubOptionArg() can be used to get the argument
 * for that option. 
 *
 */
public class GetSubOpt {

    /**
     * Delimiter between suboptions.
     */
    public final static String OPTION_DELIM = ",";

    /**
     * Delimiter between suboption and suboption argument.
     */
    public final static String VALUE_DELIM =  "=";

    /**
     * List of suboptions.
     */
    protected String subOptions;

    /**
     * The length of the suboptions.
     */
    private final int subOptionsLen;

    /**
     * Current position with in suboptions.
     */
    protected int index;

    /**
     * Last suboption found.
     */
    protected String subOption;

    /**
     * Last suboption argument found.
     */
    protected String value;

    /**
     * Prepare a GetSubOpt object.
     *
     * @param subOptions
     *   String containing the list of suboptions. This value was most likely
     *   returned as an option argument by <i>GetOpt</i>.
     */
    public GetSubOpt(String subOptions) {
	if (subOptions == null) {
	    this.subOptions = null;
	} else {
	    this.subOptions = subOptions.trim();
	}

	index = 0; 
	subOptionsLen = subOptions.length();
    }

    /**
     * Get the next suboption. The suboptions arguement is available from
     * calling <i>getSubOptionArg()</i>.
     *
     * @return
     *   The next suboption.
     * @exception IllegalArgumentException
     *   Thrown when no more suboptions remain.
     */
    public String getNextSubOption() throws IllegalArgumentException {

	subOption = null;
	value = null;

	while (subOption == null || subOption.length() == 0) {

	    if (!hasMoreSubOptions()) {
		String format =
			ResourceStrings.getString("getsubopt_end_of_optionarg");
		Object[] args = new Object[0];
		String msg = MessageFormat.format(format, args);
		throw new IllegalArgumentException(msg);
	    }

	    int optionIndex = subOptions.indexOf(OPTION_DELIM, index);
	    int valueIndex = subOptions.indexOf(VALUE_DELIM, index);

	    if (optionIndex == -1 && valueIndex == -1) {
		// Last suboption and no value.
		subOption = subOptions.substring(index);
		index = subOptionsLen;
	    } else if (valueIndex == -1 ||
			    (optionIndex != -1 && optionIndex < valueIndex)) {
		// Suboption has no value.
		subOption = subOptions.substring(index, optionIndex);
		index = optionIndex + OPTION_DELIM.length();
	    } else {
		// Suboption with value.
		subOption = subOptions.substring(index, valueIndex);
		index = valueIndex + VALUE_DELIM.length();

		boolean quoted = false;
		int endIndex;

		if (index < subOptionsLen &&
			    (subOptions.charAt(index) == '\"' ||
				subOptions.charAt(index) == '\'')) {
		    // Value is quoted.
		    endIndex =
			subOptions.indexOf(subOptions.charAt(index), index + 1);

		    // Missing close quote. 
		    if (endIndex == -1) {
			String format =
				ResourceStrings.getString(
				    "getsubopt_missing_close_quote");
			Object[] args = new Object[1];
			args[0] = subOption;
			String msg = MessageFormat.format(format, args);
			throw new IllegalArgumentException(msg);
		    }
 
		    quoted = true;
		    index++;
		} else {
		    // Value is not quoted.
		    endIndex = subOptions.indexOf(OPTION_DELIM, index);
	    
		    if (endIndex == -1) {
			endIndex = subOptionsLen;
		    }
		}

		value = subOptions.substring(index, endIndex);
		index = endIndex;

		// Skip closing quote.
		if (quoted) {
		    index++;
		}

		/*
		 * Ensure that either the end of the suboptions has been
		 * reached or the next suboption is ready for parsing. For
		 * example, quoted values must not contain characters between
		 * the closing quote and OPTION_DELIM.
		 */
		if (optionIndex >= 0) {
		    if (index < subOptionsLen &&
				!subOptions.startsWith(OPTION_DELIM, index)) {
			String format =
				ResourceStrings.getString(
				    "getsubopt_malformed_value");
			Object[] args = new Object[1];
			args[0] = subOption;
			String msg = MessageFormat.format(format, args);
			throw new IllegalArgumentException(msg);
		    }

		    index += OPTION_DELIM.length();
		}
	    }
	}

	return subOption;
    }

    /**
     * Indicates whether more suboptions exist.
     *
     * @return
     *   True if at least one more suboption exists, otherwise false.
     */
    public boolean hasMoreSubOptions() throws IllegalArgumentException {
	if (subOptions == null) {
	    return false;
	}

	// Skip over leading OPTION_DELIMs.
	while (index < subOptionsLen &&
			    subOptions.indexOf(OPTION_DELIM, index) == index) {
	    index += OPTION_DELIM.length();
	}

	/*
	 * Ensure that there really is a suboption present. If a
	 * VALUE_DELIM has been found the suboption string is missing.
	 */
	if (index < subOptionsLen &&
			    subOptions.indexOf(VALUE_DELIM, index) == index) {
	    String format =
		    ResourceStrings.getString(
			"getsubopt_value_without_suboption");
	    Object[] args = new Object[0];
	    String msg = MessageFormat.format(format, args);
	    throw new IllegalArgumentException(msg);
	}

	return (index < subOptionsLen);
    }

    /**
     * Get the current suboptions argument, or null if no argument is present.
     *
     * @return
     *   String containing the current suboptions argument, or null if the
     *   no argument is present.
     */
    public String getSubOptionArg() {
	return value;
    }
}

