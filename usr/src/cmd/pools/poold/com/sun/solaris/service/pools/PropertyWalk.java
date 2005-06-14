/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *ident	"%Z%%M%	%I%	%E% SMI"
 *
 */

package com.sun.solaris.service.pools;

import java.util.List;
import java.util.ArrayList;

/**
 * The <code>PropertyWalk</code> interface specifies the contract
 * between a pools configuration element and clients which are
 * interested in enumerating the properties of the element.
 */

public interface PropertyWalk {
	/**
	 * Walk all properties of the invoking object, calling the 
	 *
	 * @param elem The element to whom the property belongs.
	 * @param val The value representing the current element.
	 * @param user User supplied data, provided when the walk is invoked.
	 * @throws PoolsExecption If there is an error walking the property.
	 * @return 0 to continue the walk, anything else to terminate it.
	 */
	public int walk(Element elem, Value val, Object user)
	    throws PoolsException;
}
