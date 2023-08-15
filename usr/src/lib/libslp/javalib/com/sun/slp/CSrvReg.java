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

//  CSrvReg.java:    Service Registration, Client Side.
//  Author:           James Kempf
//  Created On:       Tue Feb 10 12:15:43 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 27 10:57:38 1998
//  Update Count:     49
//

package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The CSrvReg class models the client side SLP service registration
 * message.
 *
 * @author James Kempf
 */

class CSrvReg extends SrvLocMsgImpl {

    ServiceURL URL;

    // Construct a CSrvReg from the arguments. This is the SrvReg for

    CSrvReg(boolean fresh,
	    Locale locale,
	    ServiceURL urlEntry,
	    Vector scopes,
	    Vector attrs,
	    Hashtable URLSignatures,
	    Hashtable attrSignatures)
	throws ServiceLocationException {

	this.URL = urlEntry;

	// We do heavy checking of attributes here so that any registrations
	//  are correct.

	Hashtable attrHash = new Hashtable();
	int i, n = attrs.size();

	// Verify each attribute, merging duplicates in the vector
	//  and throwing an error if any duplicates have mismatched types.

	Vector attrList = new Vector();

	for (i = 0; i < n; i++) {
	    Object o = attrs.elementAt(i);

	    if (!(o instanceof ServiceLocationAttribute)) {
		throw
		    new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("not_an_attribute",
						       new Object[0]));
	    }

	    // Make a new copy of the attribute, so we can modify it.

	    ServiceLocationAttribute attr = (ServiceLocationAttribute)o;

	    ServiceLocationAttribute.mergeDuplicateAttributes(
		new ServiceLocationAttribute(attr.getId(), attr.getValues()),
		attrHash,
		attrList,
		false);
	}

	this.initialize(fresh,
			locale,
			urlEntry,
			scopes,
			attrList,
			URLSignatures,
			attrSignatures);

    }

    // Initialize the object. V1 will do it differently.

    void initialize(boolean fresh,
		    Locale locale,
		    ServiceURL urlEntry,
		    Vector scopes,
		    Vector attrs,
		    Hashtable URLSignatures,
		    Hashtable attrSignatures)
	throws ServiceLocationException {

	SLPConfig config = SLPConfig.getSLPConfig();
	SLPHeaderV2 hdr = new SLPHeaderV2(SrvLocHeader.SrvReg, fresh, locale);
	this.hdr = hdr;
	hdr.scopes = (Vector)scopes.clone();

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Parse out the URL. Ignore overflow.

	hdr.parseServiceURLOut(urlEntry,
			       config.getHasSecurity(),
			       URLSignatures,
			       baos,
			       false);

	// Parse out service type. It may be different from the
	//  service URL.

	ServiceType serviceType = urlEntry.getServiceType();

	hdr.putString(serviceType.toString(), baos);

	// Escape scope strings.

	hdr.escapeScopeStrings(scopes);

	// Parse out the scope list.

	hdr.parseCommaSeparatedListOut(scopes, baos);

	// Parse out the attribute list.

	hdr.parseAttributeVectorOut(attrs,
				    urlEntry.getLifetime(),
				    config.getHasSecurity(),
				    attrSignatures,
				    baos,
				    true);

	hdr.payload = baos.toByteArray();

    }

}
