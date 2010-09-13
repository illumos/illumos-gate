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
 * Copyright (c) 1999, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  SSrvReg.java:      Message class for SLP service registration request.
//  Author:           James Kempf
//  Created On:       Thu Oct  9 14:47:48 1997
//  Last Modified By: Jason Goldschmidt
//  Last Modified On: Thu Apr  5 14:46:29 2001
//  Update Count:     107
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SSrvReg class models the server side SLP service registration. The
 * default class does SLPv2 regs, but subclasses can do other versions
 * by redefining the initialize() and makeReply() messages.
 *
 * @author James Kempf
 */

class SSrvReg extends SrvLocMsgImpl {

    ServiceURL URL = null;	         // the service URL.
    String serviceType = "";	         // service type.
    Vector attrList = new Vector();        // ServiceLocationAttribute objects.
    Hashtable URLSignature = null;  // signature for URL.
    Hashtable attrSignature = null; // the signatures for the attributes.

    // Construct a SSrvReg from the input stream.

    SSrvReg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {

	super(hdr, SrvLocHeader.SrvReg);

	this.initialize(dis);

    }

    // Initialize the object from the input stream.

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPServerHeaderV2 hdr = (SLPServerHeaderV2)getHeader();
	StringBuffer buf = new StringBuffer();

	// Parse in the service URL

	Hashtable table = new Hashtable();

	URL =
	    hdr.parseServiceURLIn(dis,
				  table,
				ServiceLocationException.INVALID_REGISTRATION);

	URLSignature = (Hashtable)table.get(URL);

	// Parse in service type name.

	hdr.getString(buf, dis);

	// Validate and set URL type.

	ServiceType t = new ServiceType(buf.toString());

	if (!(URL.getServiceType()).isServiceURL() &&
	    !t.equals(URL.getServiceType())) {
	    URL.setServiceType(t);

	}

	// Parse in the scope list.

	hdr.parseScopesIn(dis);

	// Parse in the attribute list.

	attrSignature =
	    hdr.parseAuthenticatedAttributeVectorIn(attrList, dis, false);

	hdr.constructDescription("SrvReg",
				 "       URL=``" +
				 URL + "''\n" +
				 "       service type=``" +
				 serviceType + "''\n" +
				 "       attribute list=``" +
				 attrList + "''\n" +
				 "       URL signature=" +
				 AuthBlock.desc(URLSignature) + "\n" +
				 "       attribute signature=" +
				 AuthBlock.desc(attrSignature) + "\n");
    }

    // Return a SrvAck. We ignore the existing flag, since in V2, fresh comes
    //  in. In this case, all we need to do is clone the header.

    SrvLocMsg makeReply(boolean existing) {

	SLPServerHeaderV2 hdr =
	    ((SLPServerHeaderV2)getHeader()).makeReplyHeader();

	// Construct description.

	hdr.constructDescription("SrvAck", "");

	return hdr;

    }
}
