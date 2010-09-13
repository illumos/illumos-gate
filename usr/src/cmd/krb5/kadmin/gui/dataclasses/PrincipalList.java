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
// Class to hold a principal list
//

import java.util.Vector;
import java.util.StringTokenizer;
import java.util.Date;

public class PrincipalList {
    Kadmin Kadmin = null;
    boolean dummy;
    /*
     * Dummy data for testing
     */
    String [] dummyPL = { "first", "eisler", "hooshang", "lin", "msaltz",
			"rammarti", "thurlow", "traj", "seemam",
			"eisler/admin", "lin/admin", "msaltz/admin",
			"thurlow/admin", "george", "scott", "steve",
			"carrie", "jennifer", "penny", "lisa",
			"lobby1", "lobby2", "janitor", "rentacop1",
			"rentacop2" };

    public PrincipalList() {
	dummy = true;
    }

    public PrincipalList(Kadmin session) {
        dummy = false;
        Kadmin = session;
    }

    public String[] getPrincipalList() {
	String[] in;

	// Date pdateBefore = new Date();
	if (dummy) {
	    in = new String[dummyPL.length];
	    System.arraycopy(dummyPL, 0, in, 0, dummyPL.length);
	} else {
	    // in = Kadmin.getPrincipalList();
	    String prs = Kadmin.getPrincipalList2();
	    StringTokenizer t = new StringTokenizer(prs);
	    in = new String[t.countTokens()];
	    for (int i = 0; t.hasMoreTokens(); i++)
		in[i] = t.nextToken();
	}
	// Date pdateAfter = new Date();
	// long diff = pdateAfter.getTime() - pdateBefore.getTime();
	// String s = (new Long(diff)).toString();
	// System.out.println("  Fetched list from server in "+s+" ms");
	return in;
    }

    public String[] getPrincipalList(String realm) {
	String[] in = getPrincipalList();
	for (int i = 0; i < in.length; i++) {
	    String s = in[i];
	    int x = s.lastIndexOf("@"+realm);
	    if (x > 0)
		in[i] = new String(s.substring(0, x));
	}
	return in;
    }


    public static void main(String[] args) {
	PrincipalList p = new PrincipalList();
	String[] pl = p.getPrincipalList("");
	System.out.println("Principal List:");
	for (int i = 0; i < pl.length; i++)
	    System.out.println("  "+pl[i]);
    }
}
