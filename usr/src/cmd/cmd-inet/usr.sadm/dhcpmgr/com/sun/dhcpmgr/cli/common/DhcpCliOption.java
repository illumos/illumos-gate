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

/**
 * This class is used to represent one command line option.
 */
public class DhcpCliOption {

    /**
     * The option key.
     */
    private int option;

    /**
     * The value of the option.
     */
    private String value;

    /**
     * Constructor most likely used to create a boolean option.
     * @param option the option key value
     */
    public DhcpCliOption(int option) {

	this(option, null);

    } // constructor

    /**
     * Constructor most likely used to create a String valued option.
     * @param option the option key value
     */
    public DhcpCliOption(int option, String value) {

	this.option = option;
	this.value = value;

    } // constructor

    /**
     * Returns the option key value.
     * @return the option key value
     */
    public int getOption() {

	return option;

    } // getOption

    /**
     * Set the option key value.
     * @param option the option key value
     */
    public void setOption(int option) {

	this.option = option;

    } // setOption

    /**
     * Returns the option key value as a Character.
     * @param option the key value which needs converting.
     * @return the option key value as a Character.
     */
    public static Character getOptionCharacter(int option) {

	return (new Character((char)option));

    } // getOptionCharacter

    /**
     * Returns the option key value as a Character.
     * @return the option key value as a Character.
     */
    public Character getOptionCharacter() {

	return (getOptionCharacter(option));

    } // getOptionCharacter

    /**
     * Returns the option value.
     * @return the option value
     */
    public String getValue() {

	return value;

    } // getValue

    /**
     * Set the option value.
     * @param option the option value
     */
    public void setValue(String value) {

	this.value = value;

    } // setValue

    /**
     * Compare for equality against another object.
     * @return true if the object is another DhcpCliOption instance and
     * they are both have the same key value. The value of 'value' is
     * irrelevant.  This is primarily used by the indexOf method of the
     * ArrayList used to store the options in DhcpCliOptions.
     */
    public boolean equals(Object o) {

	if (o instanceof DhcpCliOption) {
	    DhcpCliOption op = (DhcpCliOption)o;
	    return (option == op.getOption());
	} else {
	    return false;
	}

    } // equals

    /**
     * The obligatory toString() method that returns a string representation
     * of an object of this class.
     * @return a string representation of an object of this class.
     */
    public String toString() {

	return option + "=" + value;

    } // toString

} // DhcpCliOption
