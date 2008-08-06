/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  ServiceLocationException.java : All SLP exceptions are derived from
//                                  this base class.
//  Author:           Erik Guttman
//

package com.sun.slp;

import java.util.*;
import java.text.*;

/**
 * The ServiceLocationException class is thrown when an error occurs
 * during SLP operation. The exact nature of the error is indicated
 * by the integer error codes.
 *
 * @author  Erik Guttman
 */

public class ServiceLocationException extends Exception {

    // Error codes.

    /**
     * No error.
     */

    static final short OK                     = 0;

    /**
     * The DA did not have a registration in the language locale of
     * the request, although it did have one in another language locale.
     */

    public static final short LANGUAGE_NOT_SUPPORTED     = 1;

    /**
     * An error occured while parsing a URL, attribute list, or a
     * service location template document. This error is also returned
     * from DA's when an otherwise unclassifiable internal error occurs.
     */

    public static final short PARSE_ERROR            = 2;

    /**
     * Upon registration, this error is returned if the URL is invalid or
     * if some other problem occurs with the registration. Upon deregistration
     * it is also returned if the URL is not registered.
     */


    public static final short INVALID_REGISTRATION   = 3;

    /**
     * An attempt was made to register in a scope not supported by the DA.
     * This error is also returned if an attempt is made to perform a
     * registration or deregistration on a machine where a DA is running,
     * since DA machines don't support SA functionality.
     */

    public static final short SCOPE_NOT_SUPPORTED    = 4;

    /**
     * The DA or SA receives a request for an unsupported SLP SPI.
     */
    public static final short AUTHENTICATION_UNKNOWN = 5;

    /**
     * A message for which an signature block was required is missing
     * the block.
     */

    public static final short AUTHENTICATION_ABSENT  = 6;

    /**
     * A signature block failed to authenticate.
     */

    public static final short AUTHENTICATION_FAILED  = 7;

    /**
     * The version was not supported. This is surfaced to the client as a
     * no results.
     */

    static final short VERSION_NOT_SUPPORTED  = 9;

    /**
     * The DA encountered an internal error.
     */

    static final short INTERNAL_ERROR	   = 10;

    /**
     * The DA was busy. This is not surfaced to the client.
     */


    static final short DA_BUSY		   = 11;

    /**
     * An option was received by the DA that wasn't supported. This is
     * surfaced to the client as no results.
     */

    static final short OPTION_NOT_SUPPORTED   = 12;


    /**
     * An attempt was made to update a nonexisting registration.
     */

    public static final short INVALID_UPDATE	   = 13;

    /**
     * The remote agent doesn't support the request. Not surfaced to
     * the client.
     */

    static final short REQUEST_NOT_SUPPORTED = 14;

    /**
     * For SA, the DA valid lifetime intervals for
     * different DAs do not overlap.
     */

    public static final short INVALID_LIFETIME = 15;

    // Internal error codes.

    /**
     * Operation isn't implemented.
     */

    public static final short NOT_IMPLEMENTED = 16;

    /**
     * Initialization of the network failed.
     */

    public static final short NETWORK_INIT_FAILED = 17;

    /**
     * A TCP connection timed out.
     */

    public static final short NETWORK_TIMED_OUT = 18;

    /**
     * An error occured during networking.
     */

    public static final short NETWORK_ERROR 	= 19;

    /**
     * An error occured in the client-side code.
     */

    public static final short INTERNAL_SYSTEM_ERROR	= 20;

    /*
     * Registration failed to match the service type template.
     */

    public static final short TYPE_ERROR			= 21;

    /**
     * Packet size overflow.
     */

    public static final short BUFFER_OVERFLOW 		= 22;

    /**
     * Overflow due to previous responder list being too long.
     */

    static final short PREVIOUS_RESPONDER_OVERFLOW = 100;

    // The error code for this exception.

    private short errorCode = OK;

    // The message arguments.

    private Object[] params = null;

    // allows additional information to be added to the message

    private String addendum = "";

    ServiceLocationException(short errorCode, String msgTag, Object[] params) {
	super(msgTag);

	this.params = params;
	this.errorCode = errorCode;
    }

    // Return true if this is a vaild on-the-wire error code.

    static boolean validWireErrorCode(int code) {
	return ((code >= OK) && (code <= REQUEST_NOT_SUPPORTED));

    }

    /**
     * Return the error code.
     *
     * @return The integer error code.
     */

    public short getErrorCode() {
	return errorCode;

    }

    /**
     * Return the localized message, in the default locale.
     *
     * @return The localized message.
     */

    public String getMessage() {
	return getLocalizedMessage(SLPConfig.getSLPConfig().getLocale()) +
	    addendum;

    }

    public String getLocalizedMessage(Locale locale) {
	SLPConfig conf = SLPConfig.getSLPConfig();
	return conf.formatMessage(super.getMessage(), params);

    }

    void makeAddendum(String addendum) {
	this.addendum = addendum;
    }

}
