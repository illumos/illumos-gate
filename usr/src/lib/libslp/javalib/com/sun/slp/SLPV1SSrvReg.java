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

//  SLPV1SSrvReg.java:      Message class for SLP service registration request.
//  Author:           James Kempf
//  Created On:       Thu Oct  9 14:47:48 1997
//  Last Modified By: James Kempf
//  Last Modified On: Thu Mar 25 15:30:25 1999
//  Update Count:     80
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SLPV1SSrvReg class models the server side SLPv1 service registration.
 *
 * @author James Kempf
 */

class SLPV1SSrvReg extends SSrvReg {

    // For identifying scopes.

    static private final String SCOPE_ATTR_ID = "scope";

    // Construct a SLPV1SSrvReg from the input stream.

    SLPV1SSrvReg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {

	super(hdr, dis);

    }

    // Initialzie the object from the stream.

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPHeaderV1 hdr = (SLPHeaderV1)getHeader();
	StringBuffer buf = new StringBuffer();

	// Parse in the service URL

	Hashtable table = new Hashtable();

	URL =
	    hdr.parseServiceURLIn(dis,
				  true,
				ServiceLocationException.INVALID_REGISTRATION);

	serviceType = URL.getServiceType().toString();

	// Parse in the attribute list.

	attrList = hdr.parseAttributeVectorIn(dis);

	// Get the scopes. Note that if there's no scope, the request
	//  will automatically be rejected as SCOPE_NOT_SUPPORTED.

	int i, n = attrList.size();
	Vector scopes = new Vector();

	for (i = 0; i < n; i++) {
	    ServiceLocationAttribute attr =
		(ServiceLocationAttribute)attrList.elementAt(i);
	    String id = attr.getId().toLowerCase().trim();

	    if (id.equals(SCOPE_ATTR_ID)) {
		Vector vals = attr.getValues();
		int j, m = vals.size();

		for (j = 0; j < m; j++) {
		    Object o = vals.elementAt(j);

		    // Must be a string in v1!

		    if (!(o instanceof String)) {
			throw
			    new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"v1_scope_format",
				new Object[] {vals});

		    }

		    String scope = (String)o;

		    hdr.validateScope(scope);

		    scopes.addElement(scope);
		}
	    }
	}

	// If the vector is empty, then add empty string as the scope name.
	//  This will cause the service table to throw the registration
	//  as scope not supported. If unscoped regs are supported, then
	//  change to default scope.

	if (scopes.size() <= 0) {

	    if (!SLPConfig.getSLPConfig().getAcceptSLPv1UnscopedRegs()) {
		scopes.addElement("");

	    } else {
		scopes.addElement(Defaults.DEFAULT_SCOPE);

	    }
	}

	hdr.scopes = scopes;

	// Check if the registration is fresh or not.

	hdr.fresh = true;

	// Perform lookup for existing.

	ServiceStore.ServiceRecord rec =
	    ServiceTable.getServiceTable().getServiceRecord(URL, hdr.locale);

	if (rec != null) {

	    // Check scopes.

	    Vector recScopes = (Vector)rec.getScopes().clone();

	    DATable.filterScopes(recScopes, scopes, true);

	    // If it is registered in the same scopes, then it is considered
	    //  to be the same. Otherwise, it replaces.

	    if (recScopes.size() == 0) {
		hdr.fresh = false;

	    }
	}

	hdr.constructDescription("SrvReg",
				 "       URL=``" + URL + "''\n" +
				 "       attribute list=``" +
				 attrList + "''\n");

    }

    // Return a SrvAck.

    SrvLocMsg makeReply(boolean existing) {

	SLPHeaderV1 hdr = ((SLPHeaderV1)getHeader()).makeReplyHeader();

	hdr.fresh = existing;

	// Construct description.

	hdr.constructDescription("SrvAck", "");

	return hdr;

    }
}
