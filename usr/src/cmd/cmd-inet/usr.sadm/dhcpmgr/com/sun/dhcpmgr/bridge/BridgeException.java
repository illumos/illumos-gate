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

package com.sun.dhcpmgr.bridge;

import java.text.MessageFormat;

/**
 * This class is the superclass for all exceptions (other than core java
 * exceptions) thrown by the server and JNI routines.
 */
public class BridgeException extends Exception {

    /**
     * Arguments to use when formatting the message for the exception.
     */
    protected Object [] args = null;

    /**
     * Simplest constructor.
     */
    public BridgeException() {
	super("internal_error");
    } // constructor
    
    /**
     * Constructor that provides a msgid.
     * @param msgid ResourceBundle id to link to this exception.
     */
    public BridgeException(String msgid) {
	super(msgid);
    } // constructor

    /**
     * Constructor that provides a msgid and an argument to the message.
     * @param msgid ResourceBundle id to link to this exception.
     * @param args array of arguments to be used in format of message.
     */
    public BridgeException(String msgid, Object [] args) {
	super(msgid);
	this.args = args;
    } // constructor

    /**
     * Constructor that provides a msgid and an argument to the message.
     * @param msgid ResourceBundle id to link to this exception.
     * @param arg argument to be used in format of exception message.
     */
    public BridgeException(String msgid, String arg) {
	super(msgid);
	args = new Object[1];
	args[0] = arg;
    } // constructor

    /**
     * Override of superclass getMessage(). Builds a message using the
     * msgid and args (if any) that were provided at instantiation.
     * @return message for the exception.
     */
    public String getMessage() {
	String message = null;
	String messageId = super.getMessage();

	try {
	    if (args != null) {
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString(messageId));
		message = form.format(args);
	    } else {
		message = ResourceStrings.getString(messageId);
	    }
	} catch (Throwable e) {
	    message = messageId;
	}

	return (message);
    } // getMessage

} // BridgeException
