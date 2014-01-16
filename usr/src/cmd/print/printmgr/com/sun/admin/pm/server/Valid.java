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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Valid
 * Check user input. We are mostly concerned with characters
 * we know will cause problems for the sub-system.
 * multi-byte characters will be screened out by the gui.
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

public class  Valid {

    static String spaces = "\t ";
    /* JSTYLED */
    static String badmetas = "\"\\$^&*(){}`'|;:?<>";
    /* JSTYLED */
    static String baddestmetas = "\"\\$^&*(){}`'|;?<>";

    // lpadmin used to only take 14.
    static int validlocalprinternamelength = 1024;
    // MAXHOSTNAMELEN + MAXPATHLEN seems reasonable.
    static int validremoteprinternamelength = 1280;

    static int validdestinationlength = 1023;	// BUFSIZ-1 seems generous
    static int validcommentlength = 256;	// From admintool
    static int validservernamelength = 256; 	// MAXHOSTNAMELEN = 256
    static int validusernamelength = 128;	// LOGNAME_MAX = 8 but since
						// it's not enforced ...
    static int validmakelength = 256;		// MAXNAMELEN = 256

    //
    // main for testing
    //
    public static void main(String[] args) {
	String[] users_arr = { "one", "two", "th`ee" };
	try {
		System.out.println(localPrinterName("foo/bar"));
		System.out.println(comment("abad:comment"));
		System.out.println(device("/dev/term/a"));
		System.out.println(printerType("  "));
		System.out.println(serverName(",bad"));
		System.out.println(users(users_arr));
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	System.exit(0);
    }

    //
    // Valid comment
    //
    public static boolean comment(String cstr)
    {
	Debug.message("SVR: Valid.comment()");
	Debug.message("SVR: comment=" + cstr);

	if (cstr == null)
		return (false);
	if (cstr.length() > validcommentlength)
		return (false);

	String c = cstr.substring(0, 1);
	// Causes problems in lpadmin
	if (c.equals(",")) {
		return (false);
	}
	if (c.equals("-")) {
		return (false);
	}

	return (validString(cstr, badmetas + "="));
    }

    //
    // Valid local printer name
    //
    public static boolean localPrinterName(String pn)
    {
	Debug.message("SVR: Valid.localPrinterName()");
	Debug.message("SVR: printerName=" + pn);

	if (pn == null)
		return (false);
	if (pn.length() == 0)
		return (false);
	if (pn.length() > validlocalprinternamelength)
		return (false);

	String c = pn.substring(0, 1);
	if (c.equals(".")) {
		return (false);
	}
	if (c.equals("!")) {
		return (false);
	}
	if (c.equals("=")) {
		return (false);
	}

	// Keywords for the sub-system
	if (pn.equals("_default"))
		return (false);
	if (pn.equals("_all"))
		return (false);

	return (validString(pn, badmetas + spaces + "/#:,"));
    }

    //
    // Valid remote printer name
    //
    public static boolean remotePrinterName(String pn)
    {
	Debug.message("SVR: Valid.remotePrinterName()");
	Debug.message("SVR: printerName=" + pn);

	if (pn == null)
		return (false);
	if (pn.length() == 0)
		return (false);
	if (pn.length() > validremoteprinternamelength)
		return (false);

	// Keywords for the sub-system
	if (pn.equals("_default"))
		return (false);
	if (pn.equals("_all"))
		return (false);

	String c = pn.substring(0, 1);
	if (c.equals(".")) {
		return (false);
	}
	if (c.equals("!")) {
		return (false);
	}
	if (c.equals("=")) {
		return (false);
	}

	return (validString(pn, badmetas + spaces + "/#:,"));
    }

    //
    // Valid device
    // Does it exist and is it writable.
    //
    public static boolean device(String dev)
	throws Exception
    {
	int exitvalue;

	Debug.message("SVR: Valid.device()");
	Debug.message("SVR: device=" + dev);

	if (dev == null)
		return (false);
	if (dev.length() == 0)
		return (false);
	if (dev.indexOf("://") != 0)	// don't test if it's a URI
		return (true);

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/test -w " + dev);
	exitvalue = syscmd.getExitValue();
	syscmd = null;

	if (exitvalue != 0)
		return (false);
	return (true);
    }

    //
    // Valid Printer Make
    //  Does a directory of that name exist, and is it readable.
    //

    public static boolean make(String dir)
	throws Exception
    {
	int exitvalue;

	Debug.message("SVR: Valid.make()");
	Debug.message("SVR: dir=" + dir);

	if (dir == null)
		return (false);
	if ((dir.length() == 0) || (dir.length() > validmakelength))
		return (false);

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/test -d -r " + dir);
	exitvalue = syscmd.getExitValue();
	syscmd = null;

	if (exitvalue != 0)
		return (false);
	return (true);
    }

    //
    // Valid printer type
    //
    public static boolean printerType(String pt)
	throws Exception
    {
	int exitvalue;

	Debug.message("SVR: Valid.printerType()");
	Debug.message("SVR: printerType=" + pt);

	if (pt == null)
		return (false);
	if (pt.length() == 0)
		return (false);

	if (pt.equals("/"))
		return (false);

	if (pt.indexOf(" ") != -1) {
		return (false);
	}
	if (pt.indexOf("\t") != -1) {
		return (false);
	}

	String c = pt.substring(0, 1);
	String path = "/usr/share/lib/terminfo/" + c + "/" + pt;
	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/test -r " + path);
	exitvalue = syscmd.getExitValue();
	syscmd = null;

	if (exitvalue != 0)
		return (false);
	return (true);
    }

    //
    // Valid destination
    //
    public static boolean destination(String d)
    {
	Debug.message("SVR: Valid.destination()");
	Debug.message("SVR: destination=" + d);

	if (d == null)
		return (false);
	if (d.length() == 0)
		return (false);
	if (d.length() > validdestinationlength)
		return (false);

	return (validString(d, baddestmetas + spaces));
    }

    //
    // Valid Server name
    //
    public static boolean serverName(String s)
    {
	Debug.message("SVR: Valid.serverName()");
	Debug.message("SVR: serverName=" + s);

	if (s == null)
		return (false);
	if (s.length() == 0)
		return (false);
	if (s.length() > validservernamelength)
		return (false);

	String c = s.substring(0, 1);
	if (c.equals("!")) {
		return (false);
	}
	if (c.equals("=")) {
		return (false);
	}

	return (validString(s, badmetas + spaces + "#,:"));
    }

    //
    // Users
    //
    public static boolean users(String[] u)
    {
	Debug.message("SVR: Valid.users()");
	Debug.message("SVR: users = " + PrinterDebug.arr_to_str(u));

	if (u == null) {
		return (false);
	}
	if (u.length == 0) {
		return (false);
	}

	for (int i = 0; i < u.length; i++) {
		if (u[i] == null) {
			return (false);
		}
		if (u[i].length() == 0) {
			return (false);
		}
		if (u[i].length() > validusernamelength) {
			return (false);
		}
		if (!validString(u[i], badmetas + spaces)) {
			return (false);
		}
	}
	return (true);
    }

    //
    // User
    //
    public static boolean user(String u)
    {
	Debug.message("SVR: Valid.users()");
	Debug.message("SVR: users = " + u);

	if (u == null) {
		return (false);
	}
	if (u.length() == 0) {
		return (false);
	}

	if (u == null) {
		return (false);
	}
	if (u.length() == 0) {
		return (false);
	}
	if (u.length() > validusernamelength) {
		return (false);
	}
	if (!validString(u, badmetas + spaces)) {
		return (false);
	}
	return (true);
    }


    //
    // Check to see if a string contains an invalid character
    //
    private static boolean validString(String str, String badchars)
    {
	// Can't start with a hyphen
	String start = str.substring(0, 1);
	if (start.equals("-"))
		return (false);

	char[] badchars_arr = badchars.toCharArray();

	for (int i = 0; i < badchars_arr.length; i++) {
		if (str.indexOf(badchars_arr[i]) != -1) {
			return (false);
		}
	}
	return (true);
    }
}
