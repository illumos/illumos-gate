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

//  SLPV1SAttrMsg.java: SLPv1 Attribute request for server.
//  Author:           James Kempf
//  Created On:       Fri Sep 11 13:23:28 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:39 1998
//  Update Count:     19
//



package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SLPV1SAttrMsg class models the SLP server side attribute message.
 *
 * @author James Kempf
 */

class SLPV1SAttrMsg extends SAttrMsg {

    // For creating null reply.

    SLPV1SAttrMsg() {}

    // Construct a SLPV1SAttrMsg from the byte input stream. This will

    SLPV1SAttrMsg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {

	super(hdr, dis);

    }

    // Construct an empty SLPV1SSrvMsg, for monolingual off.

    static SrvLocMsg makeEmptyReply(SLPHeaderV1 hdr)
	throws ServiceLocationException {

	SLPV1SAttrMsg msg = new SLPV1SAttrMsg();
	msg.hdr = hdr;

	msg.makeReply(new Vector(), null);

	return msg;

    }

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPHeaderV1 hdr = (SLPHeaderV1)getHeader();
	StringBuffer buf = new StringBuffer();

	// Parse in the previous responder's list.

	hdr.parsePreviousRespondersIn(dis);

	// Parse in the URL or service type.

	hdr.getString(buf, dis);

	String urlOrServiceType = buf.toString().trim();

	// Decide whether this is a service type or service URL

	try {

	    URL = new ServiceURLV1(urlOrServiceType,
				   ServiceURL.LIFETIME_DEFAULT);

	    serviceType = null;

	} catch (IllegalArgumentException ex) {

	    // Check to make sure service type is right.

	    serviceType =
		hdr.checkServiceType(urlOrServiceType.toLowerCase());

	    URL = null;
	}

	// Parse in the scope and validate it.

	hdr.getString(buf, dis);

	String scope = buf.toString().toLowerCase().trim();

	hdr.validateScope(scope);

	// Change unscoped to default.

	if (scope.length() <= 0) {
	    scope = Defaults.DEFAULT_SCOPE;

	}

	hdr.scopes = new Vector();
	hdr.scopes.addElement(scope);

	// Parse in the attribute tags.

	hdr.getString(buf, dis);

	tags =
	    hdr.parseCommaSeparatedListIn(buf.toString().trim(), true);

	// Unescape tags.

	int i, n = tags.size();

	for (i = 0; i < n; i++) {
	    String tag = (String)tags.elementAt(i);

	    // Check for starting and ending wildcards.

	    boolean wildcardStart = false;
	    boolean wildcardEnd = false;

	    if (tag.startsWith("*")) {
		wildcardStart = true;
		tag = tag.substring(1, tag.length());
	    }

	    if (tag.endsWith("*")) {
		wildcardEnd = true;
		tag = tag.substring(0, tag.length()-1);
	    }

	    tag =
		ServiceLocationAttributeV1.unescapeAttributeString(tag,
								hdr.charCode);

	    if (wildcardStart) {
		tag = "*" + tag;
	    }

	    if (wildcardEnd) {
		tag = tag + "*";
	    }

	    tags.setElementAt(tag.trim(), i);
	}

	hdr.constructDescription("AttrRqst",
				 "         " +
				 (URL != null ? ("URL=``" + URL):
				  ("service type=``" + serviceType)) +
				 "''\n" +
				 "         tags=``" + tags + "''");
    }

    // Construct an SAttrMsg payload for reply to client.

    SrvLocMsg makeReply(Vector attrs, Hashtable auth)
	throws ServiceLocationException {

	SLPHeaderV1 hdr = ((SLPHeaderV1)getHeader()).makeReplyHeader();

	// We need to check whether this is an AttrRqst by type and
	//  if the type was an abstract type. If so, we simply return
	//  an empty reply, but we print a message to the log so the problem
	//  can be fixed.

	if (serviceType != null) {
	    ServiceType type = new ServiceType(serviceType);
	    ServiceStore store = ServiceTable.getServiceTable().store;
	    Vector types = store.findServiceTypes(type.getNamingAuthority(),
						  this.hdr.scopes);

	    int i, n = types.size();

	    for (i = 0; i < n; i++) {
		String stype = (String)types.elementAt(i);
		ServiceType ttype = new ServiceType(stype);

		if (ttype.isAbstractType() &&
		    type.equals(ttype.getAbstractTypeName())) {

		    // We are out of luck!

		    SLPConfig config = SLPConfig.getSLPConfig();

		    config.writeLog("v1_abstract_type_conflict",
				    new Object[] {serviceType,
						      ttype});
		    attrs.removeAllElements();
		}
	    }
	}

	hdr.iNumReplies = attrs.size();

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	hdr.parseAttributeVectorOut(attrs, baos); // attributes

	hdr.payload = baos.toByteArray();

	hdr.constructDescription("AttrRply",
				 "        attributes=``" + attrs + "''\n");

	return hdr;
    }
}
