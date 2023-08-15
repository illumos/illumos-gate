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

//  CSrvDereg.java:   Client side Service Deregistration
//  Author:           James Kempf
//  Created On:       Tue Feb 10 13:17:41 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:38 1998
//  Update Count:     42
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SrvDeReg class models the server side SLP service deregistration.
 *
 * @author James Kempf
 */


class CSrvDereg extends SrvLocMsgImpl {

    // Construct a CSrvDereg from the arguments. This is the client side
    //  SrvDereg for transmission to the server.

    CSrvDereg(Locale locale,
	      ServiceURL url,
	      Vector scopes,
	      Vector tags,
	      Hashtable auth)
	throws ServiceLocationException {

	// Null tags argument means deregister the service URL, but it
	// can't be empty.

	if (tags != null && tags.size() <= 0) {
	    throw
		new IllegalArgumentException(
			SLPConfig.getSLPConfig().formatMessage("empty_vector",
							       new Object[0]));
	}

	this.initialize(locale, url, scopes, tags, auth);

    }

    // Initialize object. V1 will do it differently.

    void initialize(Locale locale,
		    ServiceURL url,
		    Vector scopes,
		    Vector tags,
		    Hashtable auth)
	throws ServiceLocationException {

	SLPConfig config = SLPConfig.getSLPConfig();
	SLPHeaderV2 hdr =
	    new SLPHeaderV2(SrvLocHeader.SrvDereg, false, locale);
	this.hdr = hdr;
	hdr.scopes = (Vector)scopes.clone();

	// Escape tags.

	if (tags != null) {
	    hdr.escapeTags(tags);

	} else {
	    tags = new Vector();

	}

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Escape scopes.

	hdr.escapeScopeStrings(scopes);

	// Parse out the scopes.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	// Parse out the URL. Ignore overflow.

	hdr.parseServiceURLOut(url,
			       config.getHasSecurity(),
			       auth,
			       baos,
			       false);

	// Parse out the tags.

	hdr.parseCommaSeparatedListOut(tags, baos);

	hdr.payload = baos.toByteArray();

    }

}
