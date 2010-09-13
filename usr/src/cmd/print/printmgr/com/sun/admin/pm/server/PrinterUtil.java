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
 * PrinterUtil class
 * Methods not associated with a printer instance.
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

public class  PrinterUtil {

    //
    // main for testing
    //
    public static void main(String[] args) {
	String dp = null;
	String devs[] = null;
	String printers[] = null;

	try {
        	NameService ns = new NameService("ldap");
//		checkRootPasswd("xxx");
		dp = getDefaultPrinter(ns);
		devs = getDeviceList();
		printers = getPrinterList(ns);
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	System.out.println("Default printer is:	" + dp);
	for (int i = 0; i < devs.length; i++) {
		System.out.println(devs[i]);
	}
	for (int i = 0; i < printers.length; i += 3) {
		System.out.println("printername:        " + printers[i]);
		System.out.println("servername:         " + printers[i+1]);
		System.out.println("comment:            " + printers[i+2]);
	}
	System.exit(0);
    }

    //
    // Get the default printer for a specified name space
    //
    public synchronized static String getDefaultPrinter(
	NameService ns) throws Exception
    {
	Debug.message("SVR: PrinterUtil.getDefaultPrinter()");

	String nsarg = ns.getNameService();
	String ret = DoPrinterUtil.getDefault(nsarg);
	if (ret == null) {
		return (new String(""));
	}
	return (new String(ret));
    }

    //
    // Get a list of possible printer devices for this machine.
    //
    public synchronized static String[] getDeviceList() throws Exception
    {
	Debug.message("SVR: PrinterUtil.getDeviceList()");

	String emptylist[] = new String[1];
	emptylist[0] = "";

	String ret[] = DoPrinterUtil.getDevices();
	if (ret == null) {
		return (emptylist);
	}
	return (ret);
    }

    //
    // Get the list of supported Printer Makes (Manufacturers)
    // If supported, a PPD file exists for this Make
    //
    public synchronized static String[] getMakesList() throws Exception
    {
	Debug.message("SVR: PrinterUtil.getMakesList()");

	String emptylist[] = new String[1];
	emptylist[0] = "";

	String ret[] = DoPrinterUtil.getMakes();
	if (ret == null) {
		return (emptylist);
	}
	return (ret);
    }

    public synchronized static String[] getModelsList(
				String make) throws Exception

    {
	Debug.message("SVR: PrinterUtil.getModelsList()");

	String emptylist[] = new String[1];
	emptylist[0] = "";

	String ret[] = DoPrinterUtil.getModels(make);
	return (ret);
    }

    public synchronized static String[] getPPDList(
		String make, String model) throws Exception

    {
	Debug.message("SVR: PrinterUtil.getPPDList()");

	String emptylist[] = new String[1];
	emptylist[0] = "";

	String ret[] = DoPrinterUtil.getPPDs(make, model);
	if (ret == null) {
		return (emptylist);
	}
	return (ret);
    }

    public synchronized static String[] getProbePrinter(String device)
    {
	Debug.message("SVR: PrinterUtil.getProbePrinter()");

	String ret[] = DoPrinterUtil.getProbe(device);
	return (ret);
    }


    //
    // Get a list of printers in the specified name service.
    //
    public synchronized static String[] getPrinterList(
	NameService ns) throws Exception
    {
	Debug.message("SVR: PrinterUtil.getPrinterList()");

	String emptylist[] = new String[1];
	emptylist[0] = "";

	String nsarg = ns.getNameService();
	String[] ret = DoPrinterUtil.getList(nsarg);
	if (ret == null) {
		return (emptylist);
	}
	return (ret);
    }

    //
    // Does this printer already exist in the specified
    // name service
    //
    public synchronized static boolean exists(
	String name,
	NameService ns) throws Exception
    {
	Debug.message("SVR: PrinterUtil.exists()");

	String nsname = ns.getNameService();
	return (DoPrinterUtil.exists(name, nsname));
    }

    public synchronized static boolean isLocal(
	String printername) throws Exception
    {
	Debug.message("SVR: PrinterUtil.isLocal()");

	return (DoPrinterUtil.isLocal(printername));
    }

    public synchronized static void checkRootPasswd(
	String passwd) throws Exception
    {
	DoPrinterNS.doCheckRootPasswd(passwd);
    }
}
