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

package com.sun.dhcpmgr.data;

import java.io.Serializable;

/**
 * This class represents an error which occurred during some action
 */
public class ActionError implements Serializable {

    /**
     * The name of the element that was acted upon
     */
    private String name;

    /**
     * The exception that occurred while acting on the named element
     */
    private Exception e;

    /**
     * Basic constructor.
     * @param name the element name.
     */
    public ActionError(String name) {
	this.name = name;
	e = null;
    } // constructor

    /**
     * Create a fully formed versoin of this object
     * @param name The name of the element
     * @param exception The exception which occurred
     */
    public ActionError(String name, Exception exception) {
	this.name = name;
	e = exception;
    }

    /**
     * Returns the element name.
     * @return the element name.
     */
    public String getName() {
	return name;
    } // getName

    /**
     * Sets the exception.
     * @param exception the exception to associate with the element.
     */
    public void setException(Exception e) {
	this.e = e;
    } // setException

    /**
     * Returns the exception.
     * @return the exception.
     */
    public Exception getException() {
	return e;
    } // getException
} // ActionError
