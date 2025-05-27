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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  SLPServerHeaderV2.java: SLPv2 Header Class for Server Side
//  Author:           James Kempf
//  Created On:       Wed Sep 16 08:44:31 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Jan  4 15:26:33 1999
//  Update Count:     30
//

package com.sun.slp;

import java.util.*;

import java.net.*;
import java.io.*;
import java.security.*;

/**
 * The SLPServerHeaderV2 class serves as the header class for all server side
 * SLPv2 messages.
 *
 * @author James Kempf
 */

class SLPServerHeaderV2 extends SLPHeaderV2  implements Cloneable {

    // Function code for message reply.

    int replyFunctionCode = SrvLocHeader.SrvAck;

    // For SrvLocHeader.newInstance().

    SLPServerHeaderV2() {
	super();

    }

    // Construct a header for output. Used by the client side code to
    //  construct an initial request and the server side code to construct
    //  a reply.

    SLPServerHeaderV2(int functionCode, boolean fresh, Locale locale)
	throws ServiceLocationException {
	super(functionCode, fresh, locale);

    }

    // Assign reply code based on function code type, then use superclass
    //  method to parse header.

    void parseHeader(int functionCode, DataInputStream dis)
	throws ServiceLocationException, IOException {

	// We ignore the error case here.

	switch (functionCode) {

	case SrvLocHeader.SrvReq:
	    replyFunctionCode = SrvLocHeader.SrvRply;
	    break;

	case SrvLocHeader.AttrRqst:
	    replyFunctionCode = SrvLocHeader.AttrRply;
	    break;

	case SrvLocHeader.SrvTypeRqst:
	    replyFunctionCode = SrvLocHeader.SrvTypeRply;
	    break;

	case SrvLocHeader.SrvReg: case SrvLocHeader.SrvDereg:
	    replyFunctionCode = SrvLocHeader.SrvAck;
	    break;

	    // If we get an error during creating of the DAAdvert to
	    //  reply, we need to continue and reply with DAAdvert.
	    //  This is only true for a unicast DAAdvert, though.

	case SrvLocHeader.DAAdvert:
	    replyFunctionCode = SrvLocHeader.DAAdvert;
	    break;

	    // We ignore the header error code for SAAdvert because
	    //  it is always multicast.

	}

	// We are now set up to handle any errors that may come flying out
	//  of here.

	super.parseHeader(functionCode, dis);

    }

    // Replace the superclass method with a method that parses the server
    //  side.

    SrvLocMsg parseMsg(DataInputStream dis)
	throws ServiceLocationException,
	       IOException,
	       IllegalArgumentException {

	SrvLocMsg msg = null;

	// DAAdvert needs to get it's error code parsed here because
	//  error codes are always handled in parseMsg() and it is
	//  the only server side message that has one.

	if (functionCode == SrvLocHeader.DAAdvert) {
	    errCode = (short)getInt(dis);

	}

	// Switch and convert according to function code.

	switch (functionCode) {

	case SrvLocHeader.SrvReg:
	    msg = new SSrvReg(this, dis);
	    break;

	case SrvLocHeader.SrvDereg:
	    msg = new SSrvDereg(this, dis);
	    break;

	case SrvLocHeader.SrvReq:
	    msg = new SSrvMsg(this, dis);
	    break;

	case SrvLocHeader.AttrRqst:
	    msg = new SAttrMsg(this, dis);
	    break;

	case SrvLocHeader.SrvAck:

	    // We function as our own message.

	    msg = this;
	    iNumReplies = 1;
	    break;

	case SrvLocHeader.SrvTypeRqst:
	    msg = new SSrvTypeMsg(this, dis);
	    break;

	case SrvLocHeader.DAAdvert:
	    msg = new CDAAdvert(this, dis);
	    break;

	case SrvLocHeader.SAAdvert:
	    msg = new CSAAdvert(this, dis);
	    break;

	default:
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"function_code_error",
				new Object[] {
		    Integer.valueOf(functionCode)});

	}

	// Check for size overflow.

	if (nbytes > length) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"length_overflow",
				new Object[] {
		    Integer.valueOf(nbytes), Integer.valueOf(length)});

	}

	return msg;

    }

    // Create an error reply using the reply code. Calculate the
    //  error code using the exception.

    SrvLocMsg makeErrorReply(Exception ex) {

	SrvLocHeader hdr = null;

	// Clone the header to make sure that everything else is the same.
	//  We don't want to use the same header because it may be tested
	//  elsewhere.

	try {
	    hdr = (SrvLocHeader)this.clone();

	} catch (CloneNotSupportedException exx) {

	    // We support it, so no-op.

	}

	// Re-initialize flags but not multicast, since we need to filter on it

	hdr.fresh = false;
	hdr.overflow = false;
	hdr.functionCode = replyFunctionCode;

	// We should *not* be getting a null exception down this path!

	Assert.slpassert(ex != null,
		      "null_parameter",
		      new Object[] {ex});

	if (ex instanceof ServiceLocationException) {

	    hdr.errCode = ((ServiceLocationException)ex).getErrorCode();

	    if (!ServiceLocationException.validWireErrorCode(hdr.errCode)) {
		hdr.errCode = ServiceLocationException.INTERNAL_ERROR;

	    }

	} else if (ex instanceof IllegalArgumentException ||
		   ex instanceof IOException) {
	    hdr.errCode = ServiceLocationException.PARSE_ERROR;

	} else {
	    hdr.errCode = ServiceLocationException.INTERNAL_ERROR;

	}

	// Construct header description.

	constructDescription("SrvLocMsg", "");

	return hdr;
    }

    // Return a reply header with flags properly set.

    SLPServerHeaderV2 makeReplyHeader() {

	SLPServerHeaderV2 hdr = null;

	try {
	    hdr = (SLPServerHeaderV2)this.clone();

	} catch (CloneNotSupportedException ex) {

	    // No-op, since we support it.

	}

	hdr.functionCode = replyFunctionCode;
	hdr.length = 0;
	hdr.previousResponders = null;
	hdr.scopes = null;
	hdr.overflow = false;
	hdr.fresh = false;
	hdr.mcast = false;
	hdr.nbytes = 0;

	return hdr;
    }

    // Return display string.

    public String toString() {
	return
	    getMsgType() + ":version=``" + version + "''\n" +
	    "       functionCode=``" + functionCode + "''\n" +
	    "       length=``" + length + "''" + "''\n" +
	    "       overflow=``" + overflow + "''\n" +
	    "       mcast = ``" + mcast + "''\n" +
	    "       fresh=``" + fresh + "''\n" +
	    "       locale = ``" + locale + "''\n" +
	    "       xid=``0x" + Integer.toHexString(xid) + "''\n" +
	    "       errCode=``" + errCode + "''\n" +
	    "       previousResponders=``" + previousResponders + "''\n" +
	    "       scopes=``" + scopes + "''\n" +
	    getMsgDescription();
    }

    //
    // Parsing Utilities.
    //

    // Parse in the scope list.

    void parseScopesIn(DataInputStream dis)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	getString(buf, dis);

	scopes = parseCommaSeparatedListIn(buf.toString(), true);

	// Unescape scope strings.

	unescapeScopeStrings(scopes);

	// Validate.

	DATable.validateScopes(scopes, locale);

    }

    void parsePreviousRespondersIn(DataInputStream dis)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	getString(buf, dis);

	previousResponders =
	    parseCommaSeparatedListIn(buf.toString(), true);

    }

    // Return an SLPv2 DAAdvert.

    SDAAdvert
	getDAAdvert(short xid,
		    long timestamp,
		    ServiceURL url,
		    Vector scopes,
		    Vector attrs)
	throws ServiceLocationException {

	// If scopes vector is null, then return all scopes for this
	//  DA.

	if (scopes.size() <= 0) {
	    scopes = SLPConfig.getSLPConfig().getSAConfiguredScopes();

	}

	return new SDAAdvert(this, xid, timestamp, url, scopes, attrs);

    }

}
