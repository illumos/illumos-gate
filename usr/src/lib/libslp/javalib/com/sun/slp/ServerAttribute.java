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

//  ServerAttribute.java: Attribute created on the server side only.
//  Author:           James Kempf
//  Created On:       Thu Apr 23 08:53:49 1998
//  Last Modified By: James Kempf
//  Last Modified On: Fri May  1 10:35:22 1998
//  Update Count:     9
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The ServerAttribute class models attributes on the server side.
 * The primary difference is that values substitute AttributeString
 * objects for String objects, so attributes compare according to the
 * rules of SLP matching rather than by string equality. Also,
 * an AttributeString object for the id is included, for pattern
 * matching against the id.
 *
 * @author James Kempf
 */

class ServerAttribute extends ServiceLocationAttribute {

    // The id as an attribute string.

    AttributeString idPattern = null;

    // Construct a new ServerAttribute object. Substitute AttributeString
    //  objects for strings.

    ServerAttribute(String id_in, Vector values_in, Locale locale)
	throws IllegalArgumentException {

	super(id_in, values_in);

	idPattern = new AttributeString(id, locale);

	// Substitute for string values.

	if (values != null) {
	    Object o = values.elementAt(0);

	    if (o instanceof String) {

		int i, n = values.size();

		for (i = 0; i < n; i++) {
		    String s = (String)values.elementAt(i);
		    AttributeString as = new AttributeString(s, locale);

		    values.setElementAt(as, i);

		}
	   }
	}
    }

    // Construct a ServerAttribute object from a ServiceLocationAttribute
    //  object.

    ServerAttribute(ServiceLocationAttribute attr, Locale locale) {
	this(attr.id, attr.getValues(), locale);

    }

    // Get values by changing the attribute string objects into strings.

    public Vector getValues() {
	Vector v = super.getValues();

	if ((v != null) &&
	    (v.elementAt(0) instanceof AttributeString)) {

	    int i, n = v.size();

	    for (i = 0; i < n; i++) {
		v.setElementAt(v.elementAt(i).toString(), i);

	   }
	}

	return v;

    }

}
