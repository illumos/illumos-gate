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

//  ServiceLocationEnumerator.java: Class implementing SLP enumerator.
//  Author:           James Kempf
//  Created On:       Thu May 21 14:36:55 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu May 21 14:37:21 1998
//  Update Count:     1
//

package com.sun.slp;

import java.util.*;

/**
 * The ServiceLocationEnumerator class implements an enumeration.
 * Besides the standard Enumeration classes, it implements a next()
 * method that can (but not in this implementation) throw a
 * ServiceLocationException.
 *
 * @author James Kempf
 */

class ServiceLocationEnumerator extends Object
    implements ServiceLocationEnumeration {

    // The base enumerator.

    Enumeration base;

    /**
     * The constructor simply takes an enumerator on the vector.
     */

    public ServiceLocationEnumerator(Vector v) {

	if (v != null) {
	    base = v.elements();
	} else {
	    base = (new Vector()).elements();
	}
    }

    /**
     * Pass through to the Enumerator method.
     */

    public boolean hasMoreElements() {
	return base.hasMoreElements();
    }

    /**
     * Pass through to the Enumerator method.
     */

    public Object nextElement() throws NoSuchElementException {
	return base.nextElement();
    }

    /**
     * Pass through to the Enumerator method.
     */

    public Object next() throws ServiceLocationException {
	return base.nextElement();
    }

}
