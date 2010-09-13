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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DoPrinterAdd class
 * Worker class for adding local and remote printers.
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

public class  DoPrinterAdd {

    public static void main(String[] args) {
	//
	// Set attributes for testing
	//
	NameService ns = new NameService();

	String file_contents[] = new String[1];
	file_contents[0] = "any";
	String user_allow_list[] = new String[1];
	user_allow_list[0] = "allow1";
	String user_deny_list[] = new String[1];
	user_deny_list[0] = "deny1";

	Printer p = new Printer(ns);
	p.setPrinterName("javatest");
	p.setPrinterType("PS");
	p.setPrintServer("zelkova");
	p.setComment("This is a comment");
	p.setDevice("/var/tmp/test");
	p.setNotify("none");
	p.setProtocol("bsd");
	p.setDestination(null);
	p.setFileContents(file_contents);
	p.setUserAllowList(user_allow_list);
	p.setIsDefaultPrinter(false);
	p.setBanner("never");
	p.setEnable(true);
	p.setAccept(true);
	p.setLocale(null);

	try {
		add(p, ns);
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
    public static void add(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterAdd.add()");

	String device = p.getDevice();
	if (device == null) {
		addRemote(p, ns);
	} else {
		addLocal(p, ns);
	}
	return;
    }

    //
    // Do the work of adding a local printer.
    //
    private static void addLocal(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterAdd.addLocal()");

	int exitvalue = 0;
	String err = null;
	String cmd = null;
	SysCommand syscmd = null;

	// Since it's local set extensions.
	// Eventually the gui should do this.
	p.setExtensions("Solaris");

	String printername = p.getPrinterName();
	String printertype = p.getPrinterType();
	String printserver = p.getPrintServer();
	String comment = p.getComment();
	String device = p.getDevice();
	String make = p.getMake();
	String model = p.getModel();
	String ppd = p.getPPD();
	String notify = p.getNotify();
	String protocol = p.getProtocol();
	String destination = p.getDestination();
	String[] file_contents = p.getFileContents();
	String[] user_allow_list = p.getUserAllowList();
	String[] user_deny_list = p.getUserDenyList();
	boolean default_printer = p.getIsDefaultPrinter();
	String banner = p.getBanner();
	boolean enable = p.getEnable();
	boolean accept = p.getAccept();

	String nameservice = ns.getNameService();
	String ppdfile = null;

	//
	// "uri" is a pseudo protocol and means that the device is
	// specified in the destination.
	//
	if ((protocol != null) && (protocol.equals("uri"))) {
		device = destination;
		destination = null;
		protocol = null;
	}

	if (ppd != null) {
		ppdfile = new String(
			DoPrinterUtil.getPPDFile(make, model, ppd));
	}

	cmd = "/usr/sbin/lpadmin -p " + printername;
	if (printserver != null)
		cmd = cmd.concat(" -s " + printserver);
	if (device != null) {
		cmd = cmd.concat(" -v " + device);

		if (device.indexOf("://") != -1)
				cmd = cmd.concat(" -m uri");
		else {
			if (destination != null)
				cmd = cmd.concat(" -m netstandard");
			else
				cmd = cmd.concat(" -m standard");
			if (ppd != null)
				cmd = cmd.concat("_foomatic");
		}
	}
	if (printertype != null)
		cmd = cmd.concat(" -T " + printertype);
	if (notify != null)
		cmd = cmd.concat(" -A " + notify);
	if (ppdfile != null) {
		cmd = cmd.concat(" -n " + ppdfile);
	}


	if (destination != null)
		cmd = cmd.concat(" -o dest=" + destination);
	if (protocol != null)
		cmd = cmd.concat(" -o protocol=" + protocol);
	if (banner != null)
		cmd = cmd.concat(" -o banner=" + banner);

	if ((file_contents != null) && (file_contents.length != 0)) {
		String tmpstr = file_contents[0];
		for (int i = 1; i < file_contents.length; i++) {
			tmpstr = tmpstr.concat("," + file_contents[i]);
		}
		cmd = cmd.concat(" -I " + tmpstr);
	} else {
		cmd = cmd.concat(" -I postscript");
	}
	if ((user_allow_list != null) && (user_allow_list.length != 0)) {
		String tmpstr = user_allow_list[0];
		for (int i = 1; i < user_allow_list.length; i++) {
			tmpstr = tmpstr.concat("," + user_allow_list[i]);
		}
		cmd = cmd.concat(" -u allow:" + tmpstr);
	}

	p.setCmdLog(cmd);
	syscmd = new SysCommand();
	syscmd.exec(cmd);

	err = syscmd.getError();
	if (syscmd.getExitValue() != 0) {
		syscmd = null;
		p.setErrorLog(err);
		throw new pmCmdFailedException(err);
	} else {
		p.setWarnLog(err);
	}
	syscmd = null;

	//
	// lpadmin won't take allow and deny lists together
	// so do the deny seperately.
	//
	if ((user_deny_list != null) && (user_deny_list.length != 0)) {
		String tmpstr = user_deny_list[0];
		for (int i = 1; i < user_deny_list.length; i++) {
			tmpstr = tmpstr.concat("," + user_deny_list[i]);
		}
		cmd = "/usr/sbin/lpadmin -p " + printername +
		    " -u deny:" + tmpstr;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	if ((comment != null) && (!comment.equals(""))) {
		//
		// Have to use a command array here since
		// exec(String) doesn't parse quoted strings.
		//
		String cmd_array[] =
			{ "/usr/sbin/lpadmin", "-p", printername,
			"-D", comment };
		cmd = "/usr/sbin/lpadmin -p " + printername + " -D " +
			"\"" + comment + "\"";
		p.setCmdLog(cmd);

		syscmd = new SysCommand();
		syscmd.exec(cmd_array);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	// If this is the default printer set it.
	// If it fails warn user.
	if (default_printer) {
		cmd = "/usr/sbin/lpadmin -d " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	// Check to see if we should enable it.
	// If it fails warn user.
	if (enable) {
		cmd = "/usr/bin/enable " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}
	// Check to see if we should accept it.
	// If it fails warn user.
	if (accept) {
		cmd = "/usr/sbin/accept " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	doFilters(p);

	//
	// Take care of name service now.
	//
	if (!nameservice.equals("system")) {
		try {
			DoPrinterNS.set("add", p, ns);
		}
		catch (Exception e) {
			p.clearLogs();
			NameService localns = new NameService();
			//
			// Back out the local printer.
			//
			try {
				DoPrinterDelete.delete(p, localns);
			}
			catch (Exception e2) {
				Debug.message("SVR:" + e2.getMessage());
			}
			p.clearLogs();
			throw (e);
		}
	}
	return;
    }

    //
    // Do the work of adding a remote printer.
    //
    private static void addRemote(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterAdd.addRemote()");

	int exitvalue = 0;
	String err = null;
	String cmd = "";
	String cmd_array[] = new String[7];
	SysCommand syscmd = null;

	String printername = p.getPrinterName();
	String printserver = p.getPrintServer();
	String comment = p.getComment();
	boolean default_printer = p.getIsDefaultPrinter();
	String nameservice = ns.getNameService();

	boolean isnismaster = false;
	if (nameservice.equals("nis")) {
		//
		// Find out if we are the nis master
		//
		String nshost = ns.getNameServiceHost();
		Host h = new Host();
		String lh = h.getLocalHostName();
		if (lh.equals(nshost))
			isnismaster = true;
		h = null;
	}

	//
	// If the name service is not system and we are
	// not the nis master then do the name service
	// update and return.
	//
	if ((!nameservice.equals("system")) && (!isnismaster)) {
		DoPrinterNS.set("add", p, ns);
		return;
	}

	cmd_array[0] = "/usr/sbin/lpadmin";
	cmd_array[1] = "-p";
	cmd_array[2] = printername;
	cmd_array[3] = "-s";
	cmd_array[4] = printserver;

	if ((comment != null) && (!comment.equals(""))) {
		cmd_array[5] = "-D";
		cmd_array[6] = comment;
	}

	//
	// Fix up cmd so we can log it.
	//
	for (int i = 0; i < cmd_array.length; i++) {
		if (cmd_array[i] == null)
			continue;
		if (i == 6) {
			cmd = cmd.concat("\"" + comment + "\"");
			continue;
		}
		cmd = cmd.concat(cmd_array[i] + " ");
	}

	p.setCmdLog(cmd);
	syscmd = new SysCommand();
	syscmd.exec(cmd_array);
	err = syscmd.getError();
	if (syscmd.getExitValue() != 0) {
		p.setErrorLog(err);
		syscmd = null;
		throw new pmCmdFailedException(err);
	}
	if (err != null) {
		p.setWarnLog(err);
	}
	syscmd = null;

	// If this is the default printer set it.
	// If it fails warn user.
	if (default_printer) {
		cmd = "/usr/sbin/lpadmin -d " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	//
	// If it's nis and we are here then we are the nis
	// master. This call will do the make for us.
	//
	if (nameservice.equals("nis")) {
		try {
			DoPrinterNS.set("add", p, ns);
		}
		catch (Exception e) {
			p.clearLogs();
			try {
				//
				// Back out the local printer.
				//
				DoPrinterDelete.delete(p, ns);
			}
			catch (Exception e2)
			{
				Debug.message("SVR:" + e2.getMessage());
			}
			p.clearLogs();
			throw e;
		}
	}
	return;
    }


    //
    // Configure filters
    // Look in /etc/lp/fd and configure each filter if it hasn't
    // already been configured.  We'll add warning messages if
    // there are problems but don't consider anything here fatal.
    //
    private static void doFilters(Printer p) throws Exception
    {
	Debug.message("SVR: DoPrinterAdd.doFilters()");

	int i = 0;
	int j = 0;
	String o = null;
	String err = null;
	String cmd = null;
	String psfilters[] = null;
	SysCommand syscmd = null;

	//
	// Get list of potential filters
	//
	cmd = "/usr/bin/ls /etc/lp/fd";
	syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		syscmd = null;
		return;
	}
	o = syscmd.getOutput();
	syscmd = null;
	if (o == null) {
		return;
	}

	StringTokenizer st = new StringTokenizer(o);
	if (st.countTokens() == 0) {
		return;
	}
	psfilters = new String[st.countTokens()];
	for (i = 0; st.hasMoreTokens(); i++) {
		psfilters[i] = st.nextToken();
	}
	//
	// Remove .fd suffix and empty slots that aren't filters.
	//
	for (i = 0; i < psfilters.length; i++) {
		if (psfilters[i].endsWith(".fd")) {
			j = psfilters[i].indexOf(".fd");
			psfilters[i] = psfilters[i].substring(0, j);
		} else {
			psfilters[i] = "";
		}
	}

	// Get list of currently configured filters
	cmd = "/usr/sbin/lpfilter -l -f all";
	syscmd = new SysCommand();
	syscmd.exec(cmd);

	o = null;
	if (syscmd.getExitValue() != 0) {
		err = syscmd.getError();
		if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
		return;
	} else {
		o = syscmd.getOutput();
	}

	for (i = 0; i < psfilters.length; i++) {
		if (psfilters[i].equals(""))
			continue;

		// If we have filters see if this one is
		// already configured.
		if (o != null) {
			if (o.indexOf("\"" + psfilters[i] + "\"") > -1)
				continue;
		}

		// Add the filter
		cmd = "/usr/sbin/lpfilter -f " + psfilters[i] +
			" -F /etc/lp/fd/" + psfilters[i] + ".fd";
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);

		if (syscmd.getExitValue() != 0) {
			err = syscmd.getError();
			if (err != null) {
				p.setWarnLog(err);
			}
		}
		syscmd = null;
	}
    }
}
