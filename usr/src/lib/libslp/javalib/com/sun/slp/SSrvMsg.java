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

//  SSrvMsg.java:     Message class for SLP service request.
//  Author:           James Kempf
//  Created On:       Thu Oct  9 13:40:16 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:38 1998
//  Update Count:     112
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SSrvMsg class models the SLP service (request, reply) message
 * server side. Subclasses for other versions can specialize the
 * initialize() and makeReply() methods.
 *
 * @author James Kempf
 */

class SSrvMsg extends SrvLocMsgImpl {

    String serviceType = "";	// service type and naming authority
    String query = "";		// the query
    String spi = "";

    protected SSrvMsg() {}

    // Construct a SSrvMsg from the byte input stream.

    SSrvMsg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, SrvLocHeader.SrvReq);

	this.initialize(dis);

    }

    // Initialize the message from the input stream.

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPServerHeaderV2 hdr = (SLPServerHeaderV2)getHeader();
	StringBuffer buf = new StringBuffer();

	// First get the previous responder.

	hdr.parsePreviousRespondersIn(dis);

	// Get the service type.

	hdr.getString(buf, dis);

	serviceType = buf.toString();

	if (serviceType.length() <= 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"srq_stype_missing",
				new Object[0]);
	}

	ServiceType t = new ServiceType(serviceType);

	serviceType = t.toString();

	// Get vector of scopes.

	hdr.getString(buf, dis);

	hdr.scopes = hdr.parseCommaSeparatedListIn(buf.toString(), true);

	// Validate, but check for empty if solicitation for DAAdvert
	//  or SAAdvert.

	if (hdr.scopes.size() <= 0) {
	    if (!t.equals(Defaults.DA_SERVICE_TYPE) &&
		!t.equals(Defaults.SA_SERVICE_TYPE)) {
		throw
		    new ServiceLocationException(
					ServiceLocationException.PARSE_ERROR,
					"no_scope_vector",
					new Object[0]);
	    }
	} else {

	    // Unescape scope strings.

	    hdr.unescapeScopeStrings(hdr.scopes);

	    DATable.validateScopes(hdr.scopes, hdr.locale);

	}

	// Get the query.

	hdr.getString(buf, dis);

	query = buf.toString();

	// Get the SPI

	hdr.getString(buf, dis);

	spi = buf.toString();

	hdr.constructDescription("SrvRqst",
				 "        service type=``" +
				 serviceType + "''\n" +
				 "        query=``" +
				 query + "''\n" +
				 "        spi=``" +
				 spi + "''");
    }

    // Construct a SSrvMsg from the arguments. This will be a SrvRply
    //  for transmission to the client.

    SrvLocMsg makeReply(Hashtable urls, Hashtable URLSignatures)
	throws ServiceLocationException {

	SLPServerHeaderV2 hdr =
	    ((SLPServerHeaderV2)getHeader()).makeReplyHeader();

	hdr.iNumReplies = urls.size();
	// keep this info so SAs can drop 0 replies

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	int n = urls.size();

	String authDesc = "\n";

	// Write out size.

	hdr.putInt(n, baos);

	Enumeration en = urls.keys();

	int nurls = 0;

	// Write out the members of the list, including the lifetime.

	while (en.hasMoreElements()) {
	    ServiceURL surl = (ServiceURL)en.nextElement();
	    Hashtable auth = null;

	    if (URLSignatures != null) {
		auth = (Hashtable)URLSignatures.get(surl);
		AuthBlock selectedAuth =
		    AuthBlock.getEquivalentAuth(spi, auth);
		auth = null;
		if (selectedAuth != null) {
		    auth = new Hashtable();
		    auth.put(spi, selectedAuth);
		}
		authDesc =
		    authDesc + "         " + surl.toString() + ": " +
		    (auth != null ?
		     selectedAuth.toString() :
		     "No Auth Block\n");
	    }

	    // Parse out a URL entry. Check overflow. If the packet has filled
	    //  up, then break out of the loop.

	    if (hdr.parseServiceURLOut(surl,
				       (auth != null),
				       auth,
				       baos,
				       true) == false) {

		// Note that we set overflow here because there are additional
		//  URL's, but we don't have to truncate the packet.

		hdr.overflow = true;

		// We need to rewrite the size to what it should be.

		byte[] bytes = baos.toByteArray();
		baos.reset();
		SrvLocHeader.putInteger(nurls, baos);
		baos.write(bytes, 2, bytes.length - 2);
		break;

	    }

	    nurls++;

	}

	hdr.payload = baos.toByteArray();

	// Construct description.

	hdr.constructDescription("SrvRply",
				 "        service URLs=``" + urls + "''\n" +
				 "        auth block=" + authDesc + "\n");

	return hdr;

    }
}
