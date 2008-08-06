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

//  URLAttributeVerifier.java: Parse a service template from a URL
//  Author:           James Kempf
//  Created On:       Mon Jun 23 11:52:04 1997
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jun 11 13:24:03 1998
//  Update Count:     22
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * A URLAttributeVerifier object performs service template parsing from
 * a URL. Most of the work is done by the superclass. This class
 * takes care of opening the Reader on the URL.
 *
 * @author James Kempf
 *
 */

class URLAttributeVerifier extends AttributeVerifier {

    /**
     * Construct a URLAttributeVerifier for the file named in the parameter.
     *
     * @param url URL from which to read the template
     * @exception ServiceLocationException Error code may be:
     *				       SYSTEM_ERROR
     *					   when the URL can't be opened or
     *					   some other i/o error occurs.
     *					PARSE_ERROR
     *					    if an error occurs during
     *					    attribute parsing.
     */

    URLAttributeVerifier(String url)
	throws ServiceLocationException {

	super();

	initialize(url);

    }

    // Open a reader on the URL and initialize the attribute verifier.

    private void initialize(String urlName)
	throws ServiceLocationException {

	InputStream is = null;

	try {

	    // Open the URL.

	    URL url = new URL(urlName);

	    // Open an input stream on the URL.

	    is = url.openStream();

	    // Initialize the verifier, by parsing the file.

	    super.initialize(new InputStreamReader(is));

	} catch (MalformedURLException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"invalid_url",
				new Object[] {urlName});

	} catch (IOException ex) {

	    throw
	  new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"url_ioexception",
				new Object[] { urlName, ex.getMessage()});

	}

	try {

	    is.close();

	} catch (IOException ex) {

	}

    }
}
