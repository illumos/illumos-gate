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

//  SLPV1SDAAdvert.java: SLPv1 DAAdvert, server side.
//  Author:           James Kempf
//  Created On:       Thu Sep 10 11:00:26 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Nov  2 15:55:47 1998
//  Update Count:     27
//


package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SLPV1SDAAdvert class models the SLPv1 DAAdvert message.
 *
 * @author James Kempf
 */

class SLPV1SDAAdvert extends SDAAdvert {

    SLPV1SDAAdvert(SrvLocHeader hdr,
		   short xid,
		   long timestamp,
		   ServiceURL url,
		   Vector scopes,
		   Vector attrs)
	throws ServiceLocationException {

	super(hdr, xid, timestamp, url, scopes, attrs);

    }

    // Initialize the message.

    void initialize(long timestamp,
		    ServiceURL url,
		    Vector scopes,
		    Vector attrs)
	throws ServiceLocationException {

	// By using the incoming header, we are assured of
	//  getting the encoding required by the client.

	SLPHeaderV1 hdr = (SLPHeaderV1)this.hdr;

	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    hdr.validateScope((String)scopes.elementAt(i));

	}

	// If the only scope we support is default and we are to
	//  support unscoped regs, then advertise us
	//  as an unscoped DA. However, if default is there with others,
	//  we keep it.

	SLPConfig config = SLPConfig.getSLPConfig();

	if (config.getAcceptSLPv1UnscopedRegs() &&
	    scopes.size() <= 1 &&
	    scopes.contains(Defaults.DEFAULT_SCOPE)) {
	    scopes.removeAllElements();

	}

	// Parse out the payload.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Parse out the URL.

	hdr.parseServiceURLOut(url, false, baos);

	// Parse out the scope list. Same in V1 and V2.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	hdr.payload = baos.toByteArray();

	hdr.iNumReplies = 1;

	hdr.constructDescription("DAAdvert",
				 "         URL=``" + url + "''\n" +
				 "         scopes=``" + scopes + "''\n");

    }
}
