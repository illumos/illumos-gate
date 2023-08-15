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

//  CSrvMsg.java:     Message class for SLP service reply.
//  Author:           James Kempf
//  Created On:       Thu Oct  9 15:09:32 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 11:01:45 1998
//  Update Count:     127
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The CSrvMsg class models the SLP client side service message.
 *
 * @author James Kempf
 */

class CSrvMsg extends SrvLocMsgImpl {

    Vector serviceURLs = new Vector();		// vector of ServiceURL objects
    Hashtable  URLSignatures = new Hashtable();	// authentication block lists.

    // Only used for testing.

    protected CSrvMsg() { }

    // Construct a CSrvMsg from the byte input stream. This is a SrvRply.
    //  error code is already parsed.

    CSrvMsg(SLPHeaderV2 hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, SrvLocHeader.SrvRply);

	// Don't parse the rest if there's an error.

	if (hdr.errCode != ServiceLocationException.OK) {
	    return;
	}

	// Note that we ignore the overflow flag here, because the spec
	//  disallows partial URL entries, and so we should be able
	//  to parse in the rest of the message even if there is overflow.
	//  This is different from other messages.

	parseServiceURLsIn(hdr, dis);
    }

    // Parse in a vector of service URLs including lifetime.

    protected void parseServiceURLsIn(SLPHeaderV2 hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {

	// Get the number of service URL's.

	int i, n = hdr.getInt(dis);

	// Get the service URL's including lifetime.

	for (i = 0; i < n; i++) {

	    ServiceURL surl =
		hdr.parseServiceURLIn(dis, URLSignatures,
				      ServiceLocationException.PARSE_ERROR);

	    serviceURLs.addElement(surl);

	    // Verify the signature if any. Doing it here saves muss and
	    //  fuss in the upper layers.

	    Hashtable auth = (Hashtable) URLSignatures.get(surl);

	    if (auth != null) {
		AuthBlock.verifyAll(auth);
	    }
	}

	// Set the header number of replies received.

	hdr.iNumReplies = serviceURLs.size();

    }

    // Construct a CSrvMsg from the arguments.

    CSrvMsg(Locale locale,
	    ServiceType serviceType,
	    Vector scopes,
	    String query)
	throws ServiceLocationException {

	this.initialize(locale, serviceType, scopes, query);

    }

    // Initialize as a SLPv2 SrvRqst.

    protected void
	initialize(Locale locale,
		   ServiceType serviceType,
		   Vector scopes,
		   String query)
	throws ServiceLocationException {

	SLPHeaderV2 hdr = new SLPHeaderV2(SrvLocHeader.SrvReq, false, locale);
	this.hdr = hdr;
	hdr.scopes = (Vector)scopes.clone();

	// Set up for previous responders.

	hdr.previousResponders = new Vector();

	// Create the payload for the message.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Escape scope strings.

	hdr.escapeScopeStrings(scopes);

	// Retrieve the configured SPI, if any
	String spi = "";
	if (SLPConfig.getSLPConfig().getHasSecurity()) {
	    LinkedList spiList = AuthBlock.getSPIList("sun.net.slp.SPIs");
	    if (spiList != null && !spiList.isEmpty()) {
		// There can be only one configured SPI for UAs
		spi = (String) spiList.getFirst();
	    }
	}

	// Write out the service type.

	hdr.putString(serviceType.toString(), baos);

	// Write out scopes.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	// Write out query.

	hdr.putString(query, baos);

	// Write out SPI

	hdr.putString(spi, baos);

	hdr.payload = baos.toByteArray();
    }

    //
    // Property accessors
    //

    final Hashtable getURLSignature(ServiceURL URL) {

	return (Hashtable)(URLSignatures.get(URL));
    }

    final void setURLSignature(ServiceURL URL, Hashtable sig)
	throws IllegalArgumentException {

	if (sig == null) {
	    URLSignatures.remove(URL);
	} else {
	    URLSignatures.put(URL, sig);
	}
    }

}
