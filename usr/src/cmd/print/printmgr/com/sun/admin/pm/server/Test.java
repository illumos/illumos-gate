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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Test
 * Command line front end to Printer class
 *
 * Takes one argument - the name of a test file
 * The format of the file is:
 * Required:
 *	action=[add,delete,modify,view,list]
 *
 * Optional:
 *	printername=
 *	printertype=
 *	printserver=
 *	comment=
 *	device=
 *	notify=
 *	protocol=
 *	destination=
 *	extensions=
 *	default_printer=[true,false]
 *	banner=
 *	enable=[true,false]
 *	accept=[true,false]
 *	file_contents=[space seperated list]
 *	user_allow_list=[space seperated list]
 *	user_deny_list=[space seperated list]
 *	nameservice=[system,nis]
 *	nshost=
 *	user=
 *	passwd=
 *	locale=
 *
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

public class Test {
    public static void main(String[] args) {
	String tmpstr;
	int i;
	String testfile = "";
	if (args.length == 1) {
		testfile = args[0];
	} else {
		System.out.println("Usage: Test testfile");
		System.exit(1);
	}

	String cmd = "/usr/bin/cat " + testfile;
	String o = null;
	try {
		SysCommand syscmd = new SysCommand();
		syscmd.exec(cmd);
		if (syscmd.getExitValue() != 0) {
			System.out.println("Problem opening test file");
			System.exit(1);
		}
		o = syscmd.getOutput();
		syscmd = null;
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	o = o.concat("\n");

	String action = getToken(o, "action=");
	String printername = getToken(o, "printername=");
	String printertype = getToken(o, "printertype=");
	String printserver = getToken(o, "printserver=");
	String comment = getToken(o, "comment=");
	String device = getToken(o, "device=");
	String notify = getToken(o, "notify=");
	String banner = getToken(o, "banner=");
	String protocol = getToken(o, "protocol=");
	String destination = getToken(o, "destination=");
	String extensions = getToken(o, "extensions=");

	String[] file_contents = null;
	String[] user_allow_list = null;
	String[] user_deny_list = null;

	StringTokenizer st;
	tmpstr = getToken(o, "file_contents=");
	if (tmpstr != null) {
		st = new StringTokenizer(tmpstr);
		if (st.countTokens() != 0) {
			file_contents = new String[st.countTokens()];
			for (i = 0; st.hasMoreTokens(); i++) {
				file_contents[i] = st.nextToken();
			}
		}
	}
	tmpstr = getToken(o, "user_allow_list=");
	if (tmpstr != null) {
		st = new StringTokenizer(tmpstr);
		if (st.countTokens() != 0) {
			user_allow_list = new String[st.countTokens()];
			for (i = 0; st.hasMoreTokens(); i++) {
				user_allow_list[i] = st.nextToken();
			}
		}
	}
	tmpstr = getToken(o, "user_deny_list=");
	if (tmpstr != null) {
		st = new StringTokenizer(tmpstr);
		if (st.countTokens() != 0) {
			user_deny_list = new String[st.countTokens()];
			for (i = 0; st.hasMoreTokens(); i++) {
				user_deny_list[i] = st.nextToken();
			}
		}
	}

	boolean default_printer = false;
	boolean enable = false;
	boolean accept = false;

	tmpstr = getToken(o, "default_printer=");
	if (tmpstr != null) {
		if (tmpstr.equals("true")) {
			default_printer = true;
		}
	}
	tmpstr = getToken(o, "enable=");
	if (tmpstr != null) {
		if (tmpstr.equals("true")) {
			enable = true;
		}
	}
	tmpstr = getToken(o, "accept=");
	if (tmpstr != null) {
		if (tmpstr.equals("true")) {
			accept = true;
		}
	}

	String nameservice = getToken(o, "nameservice=");
	String nshost = getToken(o, "nshost=");
	String user = getToken(o, "user=");
	String passwd = getToken(o, "passwd=");
	String locale = getToken(o, "locale=");

	//
	// Done parsing. Let's do the work.
	//
	Debug.setDebugLevel(Debug.ALL);

	NameService ns = null;
	try {
		ns = new NameService(nameservice);
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	if (nameservice.equals("nis") || nameservice.equals("ldap")) {
		if (nshost != null)
			ns.setNameServiceHost(nshost);
		if (user != null)
			ns.setUser(user);
		if (passwd != null)
			ns.setPasswd(passwd);
	}
	try {
		ns.checkAuth();
	}
	catch (Exception e) {
		System.out.println(e);
	}

	Printer p = new Printer(ns);

	p.setPrinterName(printername);
	p.setPrinterType(printertype);
	p.setPrintServer(printserver);
	p.setFileContents(file_contents);
	p.setComment(comment);
	p.setDevice(device);
	p.setNotify(notify);
	p.setProtocol(protocol);
	p.setDestination(destination);
	p.setIsDefaultPrinter(default_printer);
	p.setBanner(banner);
	p.setEnable(enable);
	p.setAccept(accept);
	p.setUserAllowList(user_allow_list);
	p.setUserDenyList(user_deny_list);
	p.setLocale(locale);

	if (action.equals("list")) {
		String[] plist = null;
		try {
			plist  = PrinterUtil.getPrinterList(ns);
		}
		catch (Exception e)
		{
			System.out.println(e);
			System.exit(1);
		}
		if (plist == null) {
			System.out.println("No printers");
		} else {
			printPList(plist);
		}
	} else if (action.equals("view")) {
		try {
			p.getPrinterDetails();
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
		printView(p);
	} else if (action.equals("add")) {
		try {
			if (device == null) {
				p.addRemotePrinter();
			} else {
				p.addLocalPrinter();
			}
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	} else if (action.equals("modify")) {
		try {
			p.modifyPrinter();
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	} else if (action.equals("delete")) {
		try {
			p.deletePrinter();
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	} else {
		System.out.println("unknown action");
		System.exit(1);
	}
	System.out.println("============================");
	System.out.println("Commands:\n" + p.getCmdLog());
	System.out.println("Errors:\n" + p.getErrorLog());
	System.out.println("Warnings:\n" + p.getWarnLog());
	System.exit(0);
    }

    private static String getToken(String str, String sub)
    {
	int i = -1;
	int j = -1;
	String result = null;

	i = str.indexOf(sub);
	if (i != -1) {
		i = i + sub.length();
		j = str.indexOf("\n", i);
		if (j != -1) {
			result = str.substring(i, j);
			result = result.trim();
			if (result.equals(""))
				result = null;
		}
	}
	return (result);
    }

    private static void printPList(String[] list)
    {
	if (list == null)
		return;
	if (list[0].equals("")) {
		System.out.println("No printers found");
		return;
	}

	for (int i = 0; i < list.length; ) {
		System.out.println("name:		" + list[i++]);
		System.out.println("server:		" + list[i++]);
		System.out.println("comment:	" + list[i++]);
	}
    }

    private static void printView(Printer p)
    {
	String arr[];
	int i;

	System.out.println("Name:       " + p.getPrinterName());
	System.out.println("Type:       " + p.getPrinterType());
	System.out.println("Server:     " +  p.getPrintServer());
	System.out.println("Comment:    " + p.getComment());
	System.out.println("Device:     " + p.getDevice());
	System.out.println("Notify:     " + p.getNotify());
	System.out.println("Protocol:   " + p.getProtocol());
	System.out.println("Dest:       " + p.getDestination());
	System.out.println("Extensions: " + p.getExtensions());
	System.out.println("Default:    " + p.getIsDefaultPrinter());
	System.out.println("Banner:     " + p.getBanner());
	System.out.println("Enable:     " + p.getEnable());
	System.out.println("Accept:     " + p.getAccept());

	arr = p.getFileContents();
	if (arr == null) {
		System.out.println("Contents:   NULL");
	} else {
		System.out.println("Contents:");
		for (i = 0; i < arr.length; i++) {
			System.out.println("\t\t" + arr[i]);
		}
	}
	arr = p.getUserAllowList();
	if (arr == null) {
		System.out.println("Users allow: NULL");
	} else {
		System.out.println("Users allow:");
		for (i = 0; i < arr.length; i++) {
			System.out.println("\t\t" + arr[i]);
		}
	}
	arr = p.getUserDenyList();
	if (arr == null) {
		System.out.println("Users deny: NULL");
	} else {
		System.out.println("Users deny:");
		for (i = 0; i < arr.length; i++) {
			System.out.println("\t\t" + arr[i]);
		}
	}

    }
}
