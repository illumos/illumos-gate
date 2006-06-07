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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * BSTItem.java
 * Simple binary search tree implementation for help articles
 */

package com.sun.admin.pm.client;

import java.lang.*;
import com.sun.admin.pm.server.*;

public class BSTItem extends Object {
    public String key;
    public Object data;
    public int handle = UNINITIALIZED;

    static int serial = 0;
    static final int UNINITIALIZED = -1;

    public BSTItem(String newKey) {
        this(newKey, null);
    }

    public BSTItem(String newKey, Object obj) {
        key = newKey.toLowerCase();
        data = obj;
        handle = serial++;
    }

    public String toString() {
        return new String("Item " + key + " (" + handle + ")");
    }

    public int compare(BSTItem otherItem, boolean exact) {

        return compare(otherItem.key, exact);
    }


    public int compare(BSTItem otherItem) {
        return compare(otherItem, true);
    }

    public int compare(String otherKey) {
        return compare(otherKey, true);
    }


    public int compare(String otherKey, boolean exact) {

        /*
         * System.out.println(this.toString() + " comparing " +
         * (exact ? "exact" : "partial") + " to " + otherKey);
         */

        int rv = 0;

        if (otherKey != null && otherKey != "")
            rv = exact ?
                key.compareTo(otherKey) :
                compareSub(otherKey.toLowerCase());

	/*
	 *  System.out.println(
	 *	"Compare: " + key + " to " + otherKey + " -> " + rv);
	 */

        return rv;
    }


    public int compareSub(String s) {
        Debug.info("HELP:  compareSub: " + key + " to " + s);

        int rv = 0;
        try {
            rv = key.substring(0, s.length()).compareTo(s);
        } catch (Exception x) {
            Debug.info("HELP:  compareSub caught: " + x);
            rv = -1;
        }
        return rv;
    }
}
