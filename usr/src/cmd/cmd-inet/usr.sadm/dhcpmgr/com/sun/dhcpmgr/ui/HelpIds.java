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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.util.*;

public class HelpIds {
    private ResourceBundle bundle;
    
    public HelpIds(String bundleName) throws MissingResourceException {
	bundle = ResourceBundle.getBundle(bundleName);
    }
        
    public String getFilePath(String key) {
	try {
	    /*
	     * The original version of this code was:
	     * if (bundle.getLocale().toString().length() == 0) {
	     * bug 4177489 causes that not to work correctly, so for the moment
	     * we *require* that each key in a locale contain a relative
	     * path, otherwise it is assumed we're in the default locale and
	     * proceed with the default location.
	     */
	    String s = bundle.getString(key);
	    if (s.indexOf('/') == -1) {
	    	// Not localized, use the default location
		return "/usr/sadm/admin/dhcpmgr/help/" + s;
	    } else {
	    	return "/usr/share/lib/locale/com/sun/dhcpmgr/client/help/" + s;
	    }
	} catch (Throwable e) {
	    e.printStackTrace();
	    return "";
	}
    }
}
