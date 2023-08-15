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

//  CDAAdvert.java:    Message class for SLP CDAAdvert message
//  Author:           James Kempf
//  Created On:       Fri Oct 10 10:48:05 1997
//  Last Modified By: James Kempf
//  Last Modified On: Fri Jan 29 09:24:50 1999
//  Update Count:     134
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The CDAAdvert class models the SLP DAAdvert message, client side.
 * We need to accommodate SLPv1 by using an initialize() method.
 *
 * @author James Kempf
 */


class CDAAdvert extends SrvLocMsgImpl {

    ServiceURL URL = null;		// The DA's service URL
    long  timestamp = 0;		// timestamp.
    Vector attrs = new Vector();	// Attributes
    Hashtable authBlock = null;		// Scope auth blocks.
    String spis = null;			// Supported SPIs

    // Construct a CDAAdvert from the input stream.

    CDAAdvert(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, SrvLocHeader.DAAdvert);

	this.initialize(dis);

    }

    // Initialize the object from the input stream.

    protected void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPHeaderV2 hdr = (SLPHeaderV2)getHeader();

	// Parse in the timestamp. Save bytes for auth block.

	byte[] tsBytes = new byte[4];

	timestamp = getInt32(hdr, dis, tsBytes);

	// Parse in DA's service URL.

	StringBuffer buf = new StringBuffer();

	byte[] urlBytes = hdr.getString(buf, dis);

	int lifetime = getDAURLLifetime();

	String surl = buf.toString();

	// Parse in the scope list.

	byte[] scopeBytes = hdr.getString(buf, dis);

	hdr.scopes = hdr.parseCommaSeparatedListIn(buf.toString(), true);

	// Unescape scope strigns.

	hdr.unescapeScopeStrings(hdr.scopes);

	// Validate scope list.

	DATable.validateScopes(hdr.scopes, hdr.locale);

	// Parse in attribute list.

	byte[] attrBytes = hdr.parseAttributeVectorIn(attrs, dis, false);

	// Parse in the SPI list
	byte[] spiBytes = hdr.getString(buf, dis);
	spis = buf.toString();

	// Construct bytes for auth.
	Object[] message = new Object[9];

	message[0] = tsBytes;

	// None of the strings have leading length fields, so add them here
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

	// Parse in an auth block, if there.

	authBlock = hdr.parseSignatureIn(message, dis);

	if (authBlock != null) {
	    lifetime = AuthBlock.getShortestLifetime(authBlock);

	}

	// Create URL.

	try {

	    URL = new ServiceURL(surl, lifetime);

	} catch (IllegalArgumentException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"malformed_url",
				new Object[] {ex.getMessage()});

	}

	// Validate the service URL.

	ServiceType serviceType = URL.getServiceType();

	if (!serviceType.equals(Defaults.DA_SERVICE_TYPE)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"not_right_url",
				new Object[] {URL, "DA"});

	}

	// Set number of replies to one.

	hdr.iNumReplies = 1;
    }


    // Get the timestamp.

    static private long getInt32(SrvLocHeader hdr,
				 DataInputStream dis,
				 byte[] bytes)
	throws ServiceLocationException, IOException {

	bytes[0] = (byte)dis.read();
	bytes[1] = (byte)dis.read();
	bytes[2] = (byte)dis.read();
	bytes[3] = (byte)dis.read();

	long a = (long)((char)bytes[0] & 0xFF);
	long b = (long)((char)bytes[1] & 0xFF);
	long c = (long)((char)bytes[2] & 0xFF);
	long d = (long)((char)bytes[3] & 0xFF);

	long i = a << 24;
	i += b << 16;
	i += c << 8;
	i += d;

	hdr.nbytes += 4;

	return i;
    }

    // Return true if the advert indicates that the DA is going down.

    boolean isGoingDown() {
	return (timestamp == 0);

    }

    // Return true if the advert was unsolicited.

    boolean isUnsolicited() {
	return (hdr.xid == 0);

    }

    // Set is solicited. No-op for V2, since messages already know.

    void setIsUnsolicited(boolean flag) {

    }

    // Calcualte DA URL lifetime, based on active discovery interval and
    //  granularity.

    private int getDAURLLifetime() {

	// Calculate lifetime based on maximum length of time between
	//  active discoveries. We add a fudge factor to avoid problems
	//  with scheduler granularity.

	SLPConfig config = SLPConfig.getSLPConfig();

	int disInt = config.getActiveDiscoveryInterval();
	int granInt = config.getActiveDiscoveryGranularity();

	// If the discovery interval is zero, then the granularity will be
	//  also, and active discovery is off. In principle, it doesn't
	//  matter what the DA URL interval is because active discovery
	//  won't find any, because its off.

	if (disInt <= 0) {
	    return ServiceURL.LIFETIME_MAXIMUM;

	} else {
	    int lifetime = disInt + granInt;

	    return
		(lifetime > ServiceURL.LIFETIME_MAXIMUM ?
		 ServiceURL.LIFETIME_MAXIMUM:lifetime);

	}
    }
}
