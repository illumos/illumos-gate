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

//  CAttrMsg.java: Message class for SLP attribute
//                 reply.
//  Author: James Kempf Created On: Thu Oct 9 15:17:36 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:38 1998
//  Update Count: 107
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The CAttrMsg class models the SLP client side attribute message.
 *
 * @author James Kempf
 */

class CAttrMsg extends SrvLocMsgImpl {

    // Vector of ServiceLocationAttribute objects
    Vector attrList = new Vector();
    Hashtable attrAuthBlock = null;  // auth block list for objects

    // Only used for testing.

    protected CAttrMsg() { }

    // Construct a CAttrMsg from the byte input stream.

    CAttrMsg(SLPHeaderV2 hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {

	super(hdr, SrvLocHeader.AttrRply);

	// Don't parse the rest if there's an error.

	if (hdr.errCode != ServiceLocationException.OK) {
	    return;

	}

	// Ignore if overflow.

	if (hdr.overflow) {
	    return;

	}

	// Parse in the potentially authenticated attribute list.

	attrAuthBlock =
	    hdr.parseAuthenticatedAttributeVectorIn(attrList, dis, true);

	// Verify authentication, if necessary.

	if (attrAuthBlock != null) {
	    AuthBlock.verifyAll(attrAuthBlock);
	}

	// Set the number of replies.

	hdr.iNumReplies = attrList.size();

    }

    // Construct a CAttrMsg payload from the arguments. This will be
    //   an AttrRqst message.

    CAttrMsg(Locale locale, ServiceURL url, Vector scopes, Vector tags)
	throws ServiceLocationException {

	this.hdr = new SLPHeaderV2(SrvLocHeader.AttrRqst, false, locale);

	constructPayload(url.toString(), scopes, tags);

    }

    // Construct a CAttrMsg payload from the arguments. This will be
    //   an AttrRqst message.

    CAttrMsg(Locale locale, ServiceType type, Vector scopes, Vector tags)
	throws ServiceLocationException {

	this.hdr = new SLPHeaderV2(SrvLocHeader.AttrRqst, false, locale);

	constructPayload(type.toString(), scopes, tags);

    }

    // Convert the message into bytes for the payload buffer.

    protected void constructPayload(String typeOrURL,
				    Vector scopes,
				    Vector tags)
	throws ServiceLocationException {

	SLPHeaderV2 hdr = (SLPHeaderV2)this.hdr;
	hdr.scopes = (Vector)scopes.clone();

	// Set up previous responders.

	hdr.previousResponders = new Vector();

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Write out the service type or URL.

	hdr.putString(typeOrURL, baos);

	// Escape scope strings for transmission.

	hdr.escapeScopeStrings(scopes);

	// Parse out the scopes.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	// Escape tags going out.

	hdr.escapeTags(tags);

	// Parse out the tags

	hdr.parseCommaSeparatedListOut(tags, baos);

	// Retrieve the configured SPI, if any
	String spi = "";
	if (SLPConfig.getSLPConfig().getHasSecurity()) {
	    LinkedList spiList = AuthBlock.getSPIList("sun.net.slp.SPIs");
	    if (spiList != null && !spiList.isEmpty()) {
		// There can be only one configured SPI for UAs
		spi = (String) spiList.getFirst();
	    }
	}

	hdr.putString(spi, baos);

	// Set payload.

	hdr.payload = baos.toByteArray();
    }

}
