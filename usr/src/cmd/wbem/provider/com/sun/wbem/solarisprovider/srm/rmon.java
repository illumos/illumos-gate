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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * rmon.java
 */


package com.sun.wbem.solarisprovider.srm;

import java.util.Iterator;


/**
 * Simple CLI to test ResourceMonitor class. Prints the current user, projects
 * and processor sets metrics on the stdout.
 * @author Sun Microsystems, Inc.
 */
public class rmon {

    static String usage =
"rmon [-p <pid> -u [<usr>] | -j [<prj>] | -s [<set>] -l [<cnt>] -i [<ms>] -d]";

    public  static void main(String []args) {

	int pID = -1, uID = -1, jID = -1, sID = -1;
	boolean pFlag = false, uFlag = false, jFlag = false, sFlag = false,
	lFlag = false, selected = false, debF = false;
	int loopCnt = 1, interval = 1000;
	int argc;

	ProcessDataModel pui;
	ActiveUserModel aum;
	ActiveProjectModel apm;
	ProcessAggregateDataModel padm;
	ResourceMonitor resourceMonitor = null;
	Object	sync = new Object();

	try {
	    if ((argc = args.length) > 0) {
		for (int argix = 0; argix < argc; argix++)  {
		    if (args[argix].startsWith("-u")) {
			uFlag = true; selected = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    uID = Integer.parseInt(args[++argix]);
			}
		    } else if (args[argix].startsWith("-p")) {
			pFlag = true; selected = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    pID = Integer.parseInt(args[++argix]);
			}
		    } else if (args[argix].startsWith("-j")) {
			jFlag = true; selected = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    jID = Integer.parseInt(args[++argix]);
			}
		    } else if (args[argix].startsWith("-s")) {
			sFlag = true; selected = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    sID = Integer.parseInt(args[++argix]);
			}
		    } else if (args[argix].startsWith("-l")) {
			lFlag = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    loopCnt = Integer.parseInt(args[++argix]);
			} else {
			    loopCnt = 60;
			}
		    } else if (args[argix].startsWith("-i")) {
			lFlag = true;
			if (((argix + 1) < argc) &&
				(!args[argix + 1].startsWith("-"))) {
			    interval = Integer.parseInt(args[++argix]);
			}
		    } else if (args[argix].startsWith("-d")) {
			debF = true;
		    } else {
			System.err.println(usage);
			return;
		    }
		}
	    }

	    resourceMonitor = ResourceMonitor.getHandle();
	    resourceMonitor.openDataModel(10000, 1000, 5000);
	    int ret;
	    Iterator iterator;
	    DataModel dm = null;

	    for (int l = 0; l < loopCnt; l++) {
		System.out.println("\n------- Loop cnt = "+l+" -------------");
		if (!selected || pFlag) {
		    System.out.println("\n--------- PROCESSES ----------");
		    dm = resourceMonitor.getDataModel(false);
		    iterator = dm.getProcessIterator();
		    while (iterator.hasNext()) {
			pui = (ProcessDataModel) iterator.next();
			if ((pID == -1) || ((ProcessDataModel)pui).pid == pID)
			    System.out.println(pui);
		    }
		    resourceMonitor.releaseDataModel(dm);
		}
		if (!selected || uFlag) {
		    System.out.println("\n--------- USERS ----------");
		    dm = resourceMonitor.getDataModel(false);
		    iterator = dm.getProcessIterator();
		    while (iterator.hasNext()) {
			aum = (ActiveUserModel) iterator.next();
			System.out.println(aum);
		    }
		    resourceMonitor.releaseDataModel(dm);
		}
		if (!selected || uFlag) {
		    System.out.println("\n--------- USERS PROCS ----------");
		    dm = resourceMonitor.getDataModel(false);
		    iterator = dm.getProcessIterator();
		    while (iterator.hasNext()) {
			padm = (ProcessAggregateDataModel) iterator.next();
			System.out.println(padm);
		    }
		    resourceMonitor.releaseDataModel(dm);
		}
		if (!selected || jFlag) {
		    System.out.println("\n--------- PROJECT ----------");
		    dm = resourceMonitor.getDataModel(false);
		    iterator = dm.getProcessIterator();
		    while (iterator.hasNext()) {
			apm = (ActiveProjectModel) iterator.next();
			System.out.println(apm);
		    }
		    resourceMonitor.releaseDataModel(dm);
		}
		if (!selected || jFlag) {
		    System.out.println("\n--------- USERS PROCS ----------");
		    dm = resourceMonitor.getDataModel(false);
		    iterator = dm.getProcessIterator();
		    while (iterator.hasNext()) {
			padm = (ProcessAggregateDataModel) iterator.next();
			System.out.println(padm);
		    }
		    resourceMonitor.releaseDataModel(dm);
		}
		napms(6000);
	    }

	} catch (Exception e) {
	    System.err.println(e);
	    System.err.println(usage);
	    resourceMonitor.closeDataModel();
	    return;
	}
	resourceMonitor.closeDataModel();

    } // end main

    /**
    * Waits some milliseconds.
    *
    * @param ms time to wait in milliseconds
    */
    public static void napms(int ms) {
	try {
	    Thread.sleep(ms);
	} catch (InterruptedException e) {}
    }

} // end class rmon
