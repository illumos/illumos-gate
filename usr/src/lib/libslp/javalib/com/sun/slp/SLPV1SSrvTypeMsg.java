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

//  SLPV1SSrvTypeMsg.java: SLPV1 Compatibility SrvType message
//  Author:           James Kempf
//  Created On:       Mon Sep 14 10:49:05 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:39 1998
//  Update Count:     11
//


package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SLPV1SSrvTypeMsg class models the SLPv1 service type request message.
 *
 * @author James Kempf
 */


class SLPV1SSrvTypeMsg extends SSrvTypeMsg {

    // Construct a SLPV1SSrvTypeMsg from the byte input stream. This will be
    //  a SrvTypeRqst.

    SLPV1SSrvTypeMsg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException  {

	super(hdr, dis);

    }

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPHeaderV1 hdr = (SLPHeaderV1)getHeader();
	StringBuffer buf = new StringBuffer();

	// First get the previous responder.

	hdr.parsePreviousRespondersIn(dis);

	// Now get naming authority.

	namingAuthority = parseNamingAuthorityIn(hdr, dis, hdr.charCode);

	// If it's IANA, make it be null.

	if (namingAuthority.equalsIgnoreCase(ServiceType.IANA)) {
	    namingAuthority = "";

	}

	// Finally get scope.

	buf.setLength(0);

	hdr.getString(buf, dis);

	String scope = buf.toString().trim().toLowerCase();

	hdr.validateScope(scope);

	// Change unscoped to default.

	if (scope.length() <= 0) {
	    scope = Defaults.DEFAULT_SCOPE;

	}

	hdr.scopes = new Vector();
	hdr.scopes.addElement(scope);

	// Construct description.

	hdr.constructDescription("SrvTypeRqst",
				 "           naming authority=``" +
				 namingAuthority + "''\n");
    }

    // Construct a SSrvTypeMsg from the arguments. This will be a
    //  SrvTypeRply for transmission to client.

    SrvLocMsg makeReply(Vector typeNames)
	throws ServiceLocationException {

	SLPHeaderV1 hdr =
	    ((SLPHeaderV1)getHeader()).makeReplyHeader();

	// Construct payload.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Edit service type names to remove nonService: and abstract types.

	int i;

	for (i = 0; i < typeNames.size(); i++) {
	    String name = (String)typeNames.elementAt(i);
	    ServiceType type = new ServiceType(name);

	    if (type.isAbstractType() || !type.isServiceURL()) {
		typeNames.removeElement(name);

	    }
	}

	hdr.iNumReplies = typeNames.size();

	hdr.putStringVector(typeNames, baos);

	hdr.payload = baos.toByteArray();

	hdr.constructDescription("SrvTypeRply",
				 "           types=``" + typeNames + "''\n");

	return hdr;
    }
}
