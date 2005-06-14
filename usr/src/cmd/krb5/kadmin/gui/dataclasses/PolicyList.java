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
// Class to hold a policy list
//

import java.util.Vector;

public class PolicyList {
    Kadmin Kadmin = null;
    boolean dummy;
    /*
     * Dummy data for testing
     */
    String [] dummyPL = { "first", "default", "admins", "engineers",
   			    "managers", "markerters", "temps", "contractors",
			    "hourly", "remote1", "remote2", "chelmsford" };

    public PolicyList() {
	dummy = true;
    }

    public PolicyList(Kadmin session) {
        dummy = false;
        Kadmin = session;
    }

    public String[] getPolicyList() {
	    String[] in;

	    if (dummy) {
		in = new String[dummyPL.length];
		System.arraycopy(dummyPL, 0, in, 0, dummyPL.length);
	    } else {
		in = Kadmin.getPolicyList();
	    }
	    return in;
    }


    public static void main(String[] args) {
        PolicyList p = new PolicyList();
        String[] pl = p.getPolicyList();
        System.out.println("Policy List:");
        for (int i = 0; i < pl.length; i++)
	    System.out.println("  "+pl[i]);
    }
}
