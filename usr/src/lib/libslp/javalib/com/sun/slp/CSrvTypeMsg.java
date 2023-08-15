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

//  CSrvTypeMsg.java: Message class for SLP service type reply
//  Author:           James Kempf
//  Created On:       Thu Oct  9 16:15:36 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:38 1998
//  Update Count:     80
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The CSrvTypeMsg class models the SLP service type reply message.
 *
 * @author James Kempf
 */

class CSrvTypeMsg extends SrvLocMsgImpl {

    // Names contain both the service type and naming authority.

    Vector serviceTypes = new Vector();  // vector of Strings

    // Only used for testing.

    protected CSrvTypeMsg() { }

    // Construct a CSrvTypeMsg from the byte input stream. This will be
    //  a SrvTypeRply.

    CSrvTypeMsg(SLPHeaderV2 hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, SrvLocHeader.SrvTypeRply);

	// Don't parse the rest if there's an error.

	if (hdr.errCode != ServiceLocationException.OK) {
	    return;
	}

	// Return if packet overflowed.

	if (hdr.overflow) {
	    return;

	}

	StringBuffer buf = new StringBuffer();

	hdr.getString(buf, dis);

	serviceTypes =
	    hdr.parseCommaSeparatedListIn(buf.toString(), true);

	// Validate service types.

	int i, n = serviceTypes.size();

	for (i = 0; i < n; i++) {

	    // Validate.

	    ServiceType type =
		new ServiceType((String)serviceTypes.elementAt(i));

	    serviceTypes.setElementAt(type, i);

	}

	// Set the number of replies.

	hdr.iNumReplies = serviceTypes.size();

    }

    // Construct a CSrvTypeMsg from the arguments. This will be
    //  a SrvTypeRqst for transmission to the server.

    CSrvTypeMsg(Locale locale, String na, Vector scopes)
	throws ServiceLocationException {

	SLPHeaderV2 hdr =
	    new SLPHeaderV2(SrvLocHeader.SrvTypeRqst, false, locale);
	this.hdr = hdr;
	hdr.scopes = (Vector)scopes.clone();

	// Convert names.

	String namingAuthority = na.toLowerCase();

	// Verify.

	if (!namingAuthority.equals(Defaults.ALL_AUTHORITIES)) {
	    ServiceType.validateTypeComponent(namingAuthority);

	}

	// Check for IANA.

	if (namingAuthority.equals(ServiceType.IANA)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"service_type_syntax",
				new Object[] { namingAuthority });
	}

	// Set up previous responders.

	hdr.previousResponders = new Vector();

	// Make payload.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Parse out the naming authority name.

	parseNamingAuthorityOut(hdr, namingAuthority, baos);

	// Escape scope strings.

	hdr.escapeScopeStrings(scopes);

	// Parse out the scope.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	hdr.payload = baos.toByteArray();

    }

    // Parse out the naming authority.

    protected void
	parseNamingAuthorityOut(SLPHeaderV2 hdr,
				String name,
				ByteArrayOutputStream baos) {

	// Write out the naming authority.

	if (name.length() <= 0) {
	    hdr.putInt(0, baos);

	} else if (name.equals(Defaults.ALL_AUTHORITIES)) {
	    hdr.putInt(0xFFFF, baos);

	} else {
	    hdr.putString(name, baos);

	}

    }

}
