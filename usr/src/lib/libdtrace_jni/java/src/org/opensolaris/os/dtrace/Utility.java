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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.io.File;

/**
 * Common functionality for all {@code org.opensolaris.os} subpackages.
 */
class Utility
{
    private static void
    loadLibrary(String paths[], String name, boolean debug)
    {
	File file;
	for (String p : paths) {
	    file = new File(p);
	    // Allows LD_LIBRARY_PATH to include relative paths
	    p = file.getAbsolutePath();
	    try {
		System.load(p + "/" + name);
		if (debug) {
		    System.out.println("loaded " + name + " from " + p);
		}
		return;
	    } catch (UnsatisfiedLinkError e) {
	    }
	}
	throw (new UnsatisfiedLinkError("Unable to find " + name));
    }

    /**
     * Loads a library.
     */
    public static void
    loadLibrary(String name, boolean debug)
    {
	String path = System.getProperty("java.library.path");
	path = path + ":/usr/lib/64"; /* Java bug 6254947 */
	String[] paths = path.split(":");

	if (debug) {
	    String root = System.getenv("ROOT");
	    if (root != null && root.length() > 0) {
		System.out.println("Prepending $ROOT to library path.");
		String[] npaths = new String[paths.length * 2];
		for (int i = 0; i < paths.length; i++) {
		    npaths[i] = root + "/" + paths[i];
		    npaths[i + paths.length] = paths[i];
		}
		paths = npaths;
	    }
	}

	loadLibrary(paths, name, debug);
    }
}
