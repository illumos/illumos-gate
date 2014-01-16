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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * DoPrinterDelete class
 * Worker class for deleting a printer.
 */

package com.sun.admin.pm.server;

import java.io.*;

public class  DoPrinterDelete {

    //
    // main for testing
    //
    public static void main(String[] args) {

	Printer p = null;
	try {
		NameService ns = new NameService();

		p = new Printer(ns);
		p.setPrinterName("javatest");

		delete(p, ns);
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	System.out.println("Commands:\n" + p.getCmdLog());
	System.out.println("Errors:\n" + p.getErrorLog());
	System.out.println("Warnings:\n" + p.getWarnLog());
	System.exit(0);
    }

    //
    // Interface to Printer object.
    //
    public static void delete(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterDelete.delete()");

	boolean success = true;
	String err = null;
	String cmd = null;
	SysCommand syscmd = null;

	String printername = p.getPrinterName();
	String nameservice = ns.getNameService();

	boolean islocal = DoPrinterUtil.isLocal(printername);

	// Take care of locally installed case first.
	if (islocal) {
		// See if printer is already rejected.
		// Don't disable so queue can drain.
		Printer curr = new Printer();
		curr.setPrinterName(printername);
		try {
			DoPrinterView.view(curr, ns);
		}
		catch (Exception e) {
			Debug.message("SVR:" + e.getMessage());
			curr.setAccept(false);
		}

		if (curr.getAccept()) {
			cmd = "/usr/sbin/reject " + printername;
			p.setCmdLog(cmd);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (err != null) {
				p.setWarnLog(err);
			}
			syscmd = null;
		}
		curr = null;
		try {
			deleteLocal(p);
		}
		catch (Exception e) {
			Debug.message("SVR:" + e.getMessage());
			success = false;
		}
	}

	//
	// Check if we already removed it from /etc/printers.conf
	//
	boolean exists;
	exists = DoPrinterUtil.exists(printername, "system");
	if (nameservice.equals("system")) {
		if (exists) {
			try {
				deleteLocal(p);
			}
			catch (Exception e) {
				Debug.message("SVR:" + e.getMessage());
				success = false;
			}
		}
	} else {
		if ((nameservice.equals("nis")) && exists) {
			//
			// Special case if we are nis master
			//
        		Host h = new Host();
			String nshost = ns.getNameServiceHost();
        		String lh = h.getLocalHostName();
        		if (lh.equals(nshost)) {
				try {
					deleteLocal(p);
				}
				catch (Exception e) {
					Debug.message("SVR:" + e.getMessage());
					success = false;
				}
			}
			h = null;
		}
		DoPrinterNS.set("delete", p, ns);
        }
	if (!success) {
		throw new pmException();
	}
	return;
    }

    private static void deleteLocal(Printer p) throws Exception
    {
	Debug.message("SVR: DoPrinterDelete.deleteLocal()");

	String cmd = null;
	String err = null;
	SysCommand syscmd = null;
	String printername = null;

	printername = p.getPrinterName();

	// Workaround for lpadmin bug not removing default
	String def = DoPrinterUtil.getDefault("system");
	if ((def != null) && (def.equals(printername))) {
		cmd = "/usr/sbin/lpadmin -x _default";
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	cmd = "/usr/sbin/lpadmin -x " + printername;
	p.setCmdLog(cmd);
	syscmd = new SysCommand();
	syscmd.exec(cmd);
	err = syscmd.getError();
	if (err != null) {
		p.setWarnLog(err);
	}
	if (syscmd.getExitValue() != 0) {
		syscmd = null;
		throw new pmException(err);
	}
    }
}
