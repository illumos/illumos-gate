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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.pntadm;

import java.util.*;

/**
 * This class provides a convenient method to retrieve resources for
 * the pntadm package.
 */
public class ResourceStrings {

    /**
     * The handle to the resource bundle for the module.
     */
    private static ResourceBundle bundle = null;
    
    /**
     * Return a string from the resource bundle.
     * @param key the key to the resource bundle string.
     * @return the resource bundle string.
     */
    public static String getString(String key) {
	String msg = null;
	try {
	    if (bundle == null) {
		bundle = ResourceBundle.getBundle(
		    "com.sun.dhcpmgr.cli.pntadm.ResourceBundle",
		    Locale.getDefault());
	    }
	    msg = bundle.getString(key);
	} catch (Throwable e) {
	    msg = new String(key);
	}
	return msg;

    } // getString

} // ResourceStrings
