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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmCalls.java
 * Debug messages
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.applet.*;
import java.io.*;
import java.util.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Class of calls to backend
 */

public class pmCalls {

/*
 * Debugging routines
 */

    public static void testout(String out) {
	Debug.info(out);
    }

    public static void debugShowPrinter(Printer p) {
	Debug.info("CLNT:  debugShowPrinter");

        if (p.getPrinterName() != null) {
	    Debug.info("CLNT:  printer " +
                            p.getPrinterName());
        }

        if (p.getPrintServer() != null)
            Debug.info("CLNT:  server " +
                             p.getPrintServer());

        if (p.getPrinterType() != null)
            Debug.info("CLNT:  printer type " +
                            p.getPrinterType());

        if (p.getComment() != null)
            Debug.info("CLNT:  Comment " +
                            p.getComment());

        if (p.getDevice() != null)
            Debug.info("CLNT:  Device " +
                            p.getDevice());

	if (p.getMake() != null)
	    Debug.info("CLNT:  Make " +
			    p.getMake());
	else
	    Debug.info("CLNT:  Make is null");

	if (p.getModel() != null)
	    Debug.info("CLNT:  Model " +
			    p.getModel());
	else
	    Debug.info("CLNT:  Model is null");

	if (p.getPPD() != null)
	    Debug.info("CLNT:  PPD " +
			    p.getPPD());
	else
	    Debug.info("CLNT:  PPD is null");

        if (p.getNotify() != null)
            Debug.info("CLNT:  Notify " +
                            p.getNotify());

	if (p.getBanner() != null)
	    Debug.info("CLNT:  Banner " + p.getBanner());

        if (p.getProtocol() != null)
            Debug.info("CLNT:  Protocol " +
                            p.getProtocol());

        if (p.getDestination() != null)
            Debug.info("CLNT:  Destination " +
                            p.getDestination());

        if (p.getFileContents() != null) {

            String filedata[] = p.getFileContents();
            String filecontents = new String();

	    Debug.info("CLNT:  File Contents: ");

            if (filedata != null) {
		for (int i = 0; i < filedata.length; i++) {
			Debug.info("        " + filedata[i]);
		}
	    }
        }

	if (p.getNotify() != null) {
	    Debug.info("CLNT:  Fault Notification: " + p.getNotify());
	}

	String ua[] = p.getUserAllowList();
        Debug.info("CLNT:  UserAllowList ");
        if (ua != null) {
		for (int i = 0; i < ua.length; i++) {
			Debug.info("        " + ua[i]);
		}
	}

        Debug.info("CLNT:  getIsDefaultPrinter is " + p.getIsDefaultPrinter());

    }

    public static void debugshowPrinterList(NameService ns) {

	String[] list;

	try {
		list = PrinterUtil.getPrinterList(ns);
		for (int i = 0; i < list.length; i++)
			Debug.info("CLNT:  " + list[i]);
	} catch (Exception e) {
		Debug.info("CLNT: debugshowPrinterList(): exception " + e);
	}

    }

}
