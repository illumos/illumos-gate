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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

//
// Filter according to pattern and sort a string array
//

import java.util.Vector;
import java.util.Date;

public class Filter {
    public String[] out;
    
    public Filter(String[] list, String pattern) {
	if (pattern == "") {
	    out = list;
	} else {
	    // Date pdateBefore = new Date();
	    Vector v = new Vector(10, 10);
	    for (int i = 0; i < list.length; i++) {
		if (list[i].indexOf(pattern) >= 0)
		    v.addElement(new String(list[i]));
	    }
	    String[] plist = new String[v.size()];
	    for (int i = 0; i < v.size(); i++) {
		plist[i] = (String)v.elementAt(i);
		// System.out.println(Plist[i]+" ");
	    }
	    out = plist;
	    // Date pdateAfter = new Date();
	    // long diff = pdateAfter.getTime() - pdateBefore.getTime();
	    // String t = (new Long(diff)).toString();
	    // System.out.println("  Filtered list in "+t+" ms");
	}
    }
}
