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

//  SDAAdvert.java:   Server Side DAAdvert Message.
//  Author:           James Kempf
//  Created On:       Tue Feb 10 15:00:39 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Nov 17 12:12:18 1998
//  Update Count:     82
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SDAAdvert class models the SLP DAAdvert message.
 *
 * @author James Kempf
 */

class SDAAdvert extends SrvLocMsgImpl {

    SDAAdvert(SrvLocHeader hdr,
	      short xid,
	      long timestamp,
	      ServiceURL url,
	      Vector scopes,
	      Vector attrs)
	throws ServiceLocationException {

	// Note that we don't need a server side header here because
	//  we will not be parsing anything in.

	try {
	    this.hdr = (SrvLocHeader)hdr.clone();

	} catch (CloneNotSupportedException ex) {

	    // We know it's supported.

	}

	this.hdr.xid = xid;
	this.hdr.functionCode = SrvLocHeader.DAAdvert;
	this.hdr.mcast = false;
	this.hdr.previousResponders = null;  // we don't want this around.
	this.hdr.errCode = ServiceLocationException.OK;
	this.hdr.overflow = false;
	this.hdr.length = 0;
	this.hdr.fresh = false;

	this.initialize(timestamp, url, scopes, attrs);

    }


    // Initialize the message.

    void
	initialize(long timestamp,
		   ServiceURL url,
		   Vector scopes,
		   Vector attrs)
	throws ServiceLocationException {

	SLPServerHeaderV2 hdr = (SLPServerHeaderV2)this.hdr;
	hdr.scopes = (Vector)scopes.clone();

	ServiceType serviceType = url.getServiceType();

	if (!serviceType.equals(Defaults.DA_SERVICE_TYPE)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"sdaadv_nondaurl",
				new Object[] {serviceType});

	}

	if (timestamp < 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"sdaadv_neg",
				new Object[0]);
	}

	// Validate scope list.

	DATable.validateScopes(scopes, hdr.locale);
	hdr.scopes = (Vector)scopes;

	// Escape scope strings.

	hdr.escapeScopeStrings(scopes);

	// Parse out the payload.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	String surl = url.toString();

	// Parse out the timestamp

	putInt32(hdr, timestamp, baos);
	byte[] timestampBytes = baos.toByteArray();

	// Parse out the URL.

	byte[] urlBytes = hdr.putString(surl, baos);

	// Parse out the scope list.

	byte[] scopeBytes =
	    hdr.parseCommaSeparatedListOut(scopes, baos);

	// Parse out the attributes.

	byte[] attrBytes = hdr.parseAttributeVectorOut(attrs,
						       url.getLifetime(),
						       false,
						       null,
						       baos,
						       false);

	// Parse out SPI list
	String spisString = "";
	// First get DA SPIs from DA SPIs property
	LinkedList spiList = AuthBlock.getSPIList("sun.net.slp.SPIs");
	if (spiList != null && !spiList.isEmpty()) {

	    StringBuffer spiBuf = new StringBuffer();
	    spiBuf.append(spiList.getFirst().toString());

	    for (int i = 1; i < spiList.size(); i++) {
		spiBuf.append(',');
		spiBuf.append(spiList.get(i).toString());
	    }
	    spisString = spiBuf.toString();
	}

	byte[] spiBytes = hdr.putString(spisString, baos);

	// Parse out auth block, if necessary.

	Hashtable auth = null;

	if (SLPConfig.getSLPConfig().getHasSecurity()) {
	    Object[] message = new Object[9];

	    // None of the strings have leading length fields, so add them here
	    message[0] = timestampBytes;

	    ByteArrayOutputStream abaos = new ByteArrayOutputStream();
	    hdr.putInteger(urlBytes.length, abaos);
	    message[1] = abaos.toByteArray();
	    message[2] = urlBytes;

	    abaos = new ByteArrayOutputStream();
	    hdr.putInteger(attrBytes.length, abaos);
	    message[3] = abaos.toByteArray();
	    message[4] = attrBytes;

	    abaos = new ByteArrayOutputStream();
	    hdr.putInteger(scopeBytes.length, abaos);
	    message[5] = abaos.toByteArray();
	    message[6] = scopeBytes;

	    abaos = new ByteArrayOutputStream();
	    hdr.putInteger(spiBytes.length, abaos);
	    message[7] = abaos.toByteArray();
	    message[8] = spiBytes;

	    auth =
		hdr.getCheckedAuthBlockList(message,
			SLPConfig.getSLPConfig().getAdvertHeartbeatTime());

	    // Parse out auth blocks.
	    baos.write((byte)(auth.size() & 0xFF));	// auth block count
	    hdr.nbytes += 1;
	    AuthBlock.externalizeAll(hdr, auth, baos);

	} else {

	    baos.write((byte)0);

	}

	// Save bytes.

	hdr.payload = baos.toByteArray();

	hdr.constructDescription("DAAdvert",
				 "        timestamp="+timestamp+"\n"+
				 "        URL="+url+"\n"+
				 "        attrs="+attrs+"\n"+
				 "        SPIs="+spisString+"\n"+
				 "        auth block="+AuthBlock.desc(auth) +
				 "\n");
    }

    // Put out the lower 32 bits of the timestamp.

    static private void
	putInt32(SrvLocHeader hdr, long i,  ByteArrayOutputStream baos) {
	baos.write((byte) ((i >> 24) & 0xFF));
	baos.write((byte) ((i >> 16) & 0xFF));
	baos.write((byte) ((i >> 8)  & 0xFF));
	baos.write((byte) (i & 0XFF));

	hdr.nbytes += 4;
    }

}
