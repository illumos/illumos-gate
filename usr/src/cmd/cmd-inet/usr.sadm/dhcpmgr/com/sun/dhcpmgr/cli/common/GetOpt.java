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
 * arguments (similar to getopt(3C)).
 * After constructing an instance of it, getNextOption() can be used
 * to get the next option. getOptionArg() can be used to get the argument for
 * that option. getNextOptionIndex() returns how many arguments are already
 * processed from the arguments list.
 *
 * This code was "borrowed" from the Viper project. We have our own copy of
 * this code, because the Viper project has deprecated their class and we
 * have had to modify the original code.
 */
public class GetOpt {
    protected int     	optind		= 0;
    protected String  	optarg		= null;
    protected String 	argv[]		= null;
    protected int 	argc		= 0;
    protected String 	optionString	= null;

    // e.g in -v (- is in 0th position)
    //
    int MINUS_POSITION = 0; 

    // e.g. in -v (v is in 1st position )
    //
    int OPTION_POSITION = 1;

    // e.g. in -vGoldrush (G is in 2nd position )
    //
    int AFTER_OPTION_POSITION = 2;

    /**
     * Constructor
     * @parameter argv  -- Array of string arguments.
     * @parameter optionString --  contains the option letters that
     *		  will be recognized;
     *		  if a letter is followed by a colon,
     *		  the option is expected to have  an  argument.
     *		  if a letter is followed by a semi-colon,
     *		  the argument to the letter is optional.
     * e.g. abdf:e
     *      legal arguments are a, b, d, f, e.
     *      f option requires a argument.
     */
    public GetOpt(String argv[], String optionString) {
	this.argv = argv;
	this.optionString = optionString;
	this.argc = argv.length;
    }

    /*
     * Returns the next valid option.
     * Throws an IllegalArgumentException
     *   a) if option is not valid or
     *   b) an option required an argument and is not provided
     * Returns -1 if no more options left.
     */
    public int getNextOption() throws IllegalArgumentException {
	char currentOption;
	optarg = null;

	// ------------------------------------------------
	// Find out if option exists

	if (optind >= argc || (argv[optind].length() < 2) ||
		argv[optind].charAt(MINUS_POSITION) != '-') {

	    return -1;
	}

	// ---------------------------------------------------
	// So see if it is a legal option

	currentOption = argv[optind].charAt(OPTION_POSITION);

	if (!isValidOption(currentOption)) {
	    optind = optind + 1;
	    String format = ResourceStrings.getString("getopt_illegal_option");
	    Object[] args = new Object[1];
	    args[0] = new Character((char)currentOption);
	    String msg = MessageFormat.format(format, args);
	    throw new IllegalArgumentException(msg);
	}

	// ------------------------------------------------------------
	// We have a legal option now, find out if it expected to have optarg.

	if (isOptionArgAllowedByOption(currentOption) &&
		OPTION_POSITION == 1) {

	    // -------------------------------------
	    // Case when optarg is given with the option itself,
	    // like -hlastgas.east. Then extract the optarg out.

	    if (argv[optind].length() != 2) {
		optarg = argv[optind].substring(AFTER_OPTION_POSITION);
		optind++;
	    }
	    // ------------------------------------------
	    // Case when optarg is not provided, return error if it was
	    // mandatory

	    else if (optind+1 >= argc) {
		optind++;
		if (isOptionArgMandatoryByOption(currentOption)) {
		    String format =
			ResourceStrings.getString("getopt_requires_argument");
		    Object[] args = new Object[1];
		    args[0] = new Character((char)currentOption);
		    String msg = MessageFormat.format(format, args);
		    throw new IllegalArgumentException(msg);
		}
	    }
	    // ------------------------------------------------
	    // Case when there is a argument that could have been used
	    // as a optarg, but actually it is just another option.

	    else if ((argv[optind+1].length() > MINUS_POSITION) &&
		   (argv[optind+1].charAt(MINUS_POSITION) == '-') &&
		   (isValidOption(argv[optind+1].charAt(OPTION_POSITION)))) {
		optind++;
		if (isOptionArgMandatoryByOption(currentOption)) {
		    String format =
			ResourceStrings.getString("getopt_requires_argument");
		    Object[] args = new Object[1];
		    args[0] = new Character((char)currentOption);
		    String msg = MessageFormat.format(format, args);
		    throw new IllegalArgumentException(msg);
		}
	    }

	    // --------------------------------------------
	    // Finally the good case

	    else {
		optarg = argv[++optind];
		optind++;
	    }

	    OPTION_POSITION = 1;

	} else if (isOptionArgMandatoryByOption(currentOption)) {
	    String format = ResourceStrings.getString("getopt_cannot_group");
	    Object[] args = new Object[1];
	    args[0] = new Character((char)currentOption);
	    String msg = MessageFormat.format(format, args);
	    throw new IllegalArgumentException(msg);
	} else if (argv[optind].length() == OPTION_POSITION + 1) {
	    OPTION_POSITION = 1;
	    optind++;
	} else {	// illegal argument supplied for option
	    OPTION_POSITION++;
	}
	return currentOption;
    }

    /**
     * Returns the argument for the option being handled.
     */
    public String getOptionArg() {
	return optarg;
    }

    /**
     * Returns true if option is a valid option
     */
    private boolean isValidOption(char c) {
	if ((c == ':') || (optionString.indexOf(c) == -1)) {
	    return false;
	} else {
	    return true;
	}
    }

    /**
     * Returns true if option provided needs a argument.
     * throws exception if option is not a valid option at first place.
     */
    private boolean isOptionArgMandatoryByOption(char option) {
	int x = option;
	if (isValidOption(option)
	   && (optionString.length() > optionString.indexOf(option) + 1)
	   && (optionString.charAt(optionString.indexOf(option) + 1) == ':'))
	    return true;
	else
	    return false;
    }

    /**
     * Returns how many arguments are already processed by the getNextOption()
     * function. The other way to look at it is what argument is going to be
     * processed by getNextOption() method next.
     */
    public int getNextOptionIndex() {
	return optind;
    }

    /**
     * Returns true if option provided allows a argument.
     * throws exception if option is not a valid option at first place.
     */
    private boolean isOptionArgAllowedByOption(char option) {
	int x = option;
	if (isValidOption(option)
	   && (optionString.length() > optionString.indexOf(option) + 1)
	   && ((optionString.charAt(optionString.indexOf(option) + 1) == ':') ||
		(optionString.charAt(optionString.indexOf(option) + 1) == ';')))
	    return true;
	else
	    return false;
    }
}
