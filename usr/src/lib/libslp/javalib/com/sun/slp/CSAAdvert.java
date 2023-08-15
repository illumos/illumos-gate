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

//  CSAAdvert.java:    Message class for SLP CSAAdvert message
//  Author:           James Kempf
//  Created On:       Fri Oct 10 10:48:05 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:41 1998
//  Update Count:     95
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The CSAAdvert class models the SLP SAAdvert message, client side.
 *
 * @author James Kempf
 */


class CSAAdvert extends SrvLocMsgImpl {

    ServiceURL URL = null;	// The DA's service URL
    Hashtable authBlock = null;	// Scope auth blocks.
    Vector attrs = new Vector(); // The attributes.

    // Construct a CSAAdvert from the input stream.

    CSAAdvert(SLPHeaderV2 hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, SrvLocHeader.SAAdvert);

	// Parse in SA's service URL.

	StringBuffer buf = new StringBuffer();

	byte[] urlBytes = hdr.getString(buf, dis);

	try {

	    URL = new ServiceURL(buf.toString(), ServiceURL.LIFETIME_NONE);

	} catch (IllegalArgumentException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"malformed_url",
				new Object[] {ex.getMessage()});

	}

	// Validate the service URL.

	ServiceType serviceType = URL.getServiceType();

	if (!serviceType.equals(Defaults.SA_SERVICE_TYPE)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"not_right_url",
				new Object[] {URL, "SA"});

	}

	// Parse in the scope list.

	byte[] scopeBytes = hdr.getString(buf, dis);

	hdr.scopes =
	    hdr.parseCommaSeparatedListIn(buf.toString(), true);

	// Unescape scopes.

	hdr.unescapeScopeStrings(hdr.scopes);

	// Validate scope list.

	DATable.validateScopes(hdr.scopes, hdr.locale);

	// Parse in attributes.

	byte attrBytes[] = hdr.parseAttributeVectorIn(attrs, dis, false);

	// Construct bytes for auth.

	Object[] message = new Object[6];

	// None of the strings have leading length fields, so add them here
	ByteArrayOutputStream abaos = new ByteArrayOutputStream();
	hdr.putInteger(urlBytes.length, abaos);
	message[0] = abaos.toByteArray();
	message[1] = urlBytes;

	abaos = new ByteArrayOutputStream();
	hdr.putInteger(attrBytes.length, abaos);
	message[2] = abaos.toByteArray();
	message[3] = attrBytes;

	abaos = new ByteArrayOutputStream();
	hdr.putInteger(scopeBytes.length, abaos);
	message[4] = abaos.toByteArray();
	message[5] = scopeBytes;

	// Parse in an auth block if there.

	authBlock = hdr.parseSignatureIn(message, dis);

	// Set number of replies.

	hdr.iNumReplies = 1;

    }
}
