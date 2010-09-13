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
package com.sun.dhcpmgr.bridge;

import java.util.*;

/**
 * This class provides a static handle to the strings in the "bridge"
 * ResourceBundle.
 */
public class ResourceStrings {

    /**
     * The handle to the ResourceBundle.
     */
    private static ResourceBundle bundle = null;
    
    /**
     * This method retrieves a string from the ResourceBundle.
     * @param key the ResourceBundle key
     * @return the message from he ResourceBundle
     */
    public static String getString(String key) {
	String msg = null;
	try {
	    if (bundle == null) {
		bundle = ResourceBundle.getBundle(
		    "com.sun.dhcpmgr.bridge.ResourceBundle",
		    Locale.getDefault());
	    }
	    msg = bundle.getString(key);
	} catch (Throwable e) {
	    msg = new String(key);
	}
	return msg;

    } // getString

} // ResourceStrings
