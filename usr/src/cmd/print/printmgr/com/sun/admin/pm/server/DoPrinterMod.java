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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DoPrinterMod class
 * Worker class for modifying a printer.
 */

package com.sun.admin.pm.server;

import java.io.*;

public class  DoPrinterMod {

    //
    // main for testing
    //
    public static void main(String[] args) {
	NameService ns = new NameService();

	String[] arr;
	arr = new String[1];

	Printer p = new Printer();

	p.setPrinterName("javatest");
	p.setPrinterType("hplaser");
	p.setPrintServer("zelkova");
	p.setComment("This is a new comment");
	p.setDevice("/var/tmp/test");
	p.setNotify("none");
	p.setProtocol("bsd");
	p.setDestination("");
	p.setIsDefaultPrinter(true);
	p.setBanner("never");
	p.setEnable(true);
	p.setAccept(false);

	arr[0] = "any";
	p.setFileContents(arr);
	arr[0] = "one";
	p.setUserAllowList(arr);
	arr[0] = "two";
	p.setUserDenyList(arr);

	p.setLocale(null);

	try {
		modify(p, ns);
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
    public static void modify(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterMod.modify()");

	Printer curr = new Printer(ns);
	curr.setPrinterName(p.getPrinterName());
	try {
		DoPrinterView.view(curr, ns);
	}
	catch (Exception e) {
		String err = curr.getErrorLog();
		p.setErrorLog(err);
		throw new pmCmdFailedException(err);
	}

	boolean islocal = DoPrinterUtil.isLocal(p.getPrinterName());
	if (islocal) {
		modifyLocal(p, curr, ns);
	} else {
		modifyRemote(p, curr, ns);
	}
	return;
    }

    //
    // Do the work of modifying a local printer.
    //
    private static void modifyLocal(
	Printer p,
	Printer curr,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterMod.modifyLocal()");

	String err = null;
	String cmd = null;
	SysCommand syscmd = null;

	// Since it's local set extensions
	// Eventually the gui should do this.
	p.setExtensions("Solaris");

	String nameservice = ns.getNameService();

	String printername = p.getPrinterName();
	String printertype = null;
	String printserver = null;
	String comment = null;
	String device = null;
	String notify = null;
	String make = null;
	String model = null;
	String ppd = null;
	String protocol = null;
	String destination = null;
	String[] file_contents = null;
	String[] user_allow_list = null;
	String[] user_deny_list = null;
	boolean default_printer = false;
	String banner = null;
	boolean enable = false;
	boolean accept = false;
	boolean isURI = false;

	boolean allow_changed = false;
	boolean default_printer_changed = false;
	boolean banner_req_changed = false;
	boolean enable_changed = false;
	boolean accept_changed = false;

	String ppdfile = null;


	//
	// Set the things that have changed.
	//
	if (!strings_equal(curr.getPrinterType(), p.getPrinterType()))
		printertype = p.getPrinterType();
	if (!strings_equal(curr.getComment(), p.getComment())) {
		comment = p.getComment();
		if (comment == null) {
			// Comment changed to empty.
			p.setComment("");
			comment = "";
		}
	}
	if (!strings_equal(curr.getDevice(), p.getDevice()))
		device = p.getDevice();

	if (!strings_equal(curr.getNotify(), p.getNotify()))
		notify = p.getNotify();

	if (!strings_equal(curr.getProtocol(), p.getProtocol())) {
		protocol = p.getProtocol();
	}

	// Need to know if the new protocol is uri or if the
	// protocol did not change and the current one is uri
	if (((protocol == null) && (curr.getProtocol() == "uri")) ||
		((protocol != null) && (protocol.equals("uri"))))  {
		isURI = true;
	}
	Debug.message("SVR:DoPrinterMod:isURI: " + isURI);
	Debug.message("SVR:DoPrinterMod:protocol: " + protocol);
	Debug.message(
	    "SVR:DoPrinterMod:curr.getProtocol(): " + curr.getProtocol());
	Debug.message("SVR:DoPrinterMod:p.getProtocol(): " + p.getProtocol());

	if (!strings_equal(curr.getDestination(), p.getDestination()))
		destination = p.getDestination();

	if ((!strings_equal(curr.getMake(), p.getMake())) ||
		(!strings_equal(curr.getModel(), p.getModel())) ||
		(!strings_equal(curr.getPPD(), p.getPPD()))) {

			model = p.getModel();
			make = p.getMake();
			ppd = p.getPPD();
		}


	if (curr.getIsDefaultPrinter() != p.getIsDefaultPrinter()) {
		default_printer = p.getIsDefaultPrinter();
		default_printer_changed = true;
	}
	if (curr.getEnable() != p.getEnable()) {
		enable = p.getEnable();
		enable_changed = true;
	}

	if (curr.getIsDefaultPrinter() != p.getIsDefaultPrinter()) {
		default_printer = p.getIsDefaultPrinter();
		default_printer_changed = true;
	}
	if (curr.getEnable() != p.getEnable()) {
		enable = p.getEnable();
		enable_changed = true;
	}

	if (curr.getIsDefaultPrinter() != p.getIsDefaultPrinter()) {
		default_printer = p.getIsDefaultPrinter();
		default_printer_changed = true;
	}
	if (curr.getEnable() != p.getEnable()) {
		enable = p.getEnable();
		enable_changed = true;
	}
	if (curr.getAccept() != p.getAccept()) {
		accept = p.getAccept();
		accept_changed = true;
	}
	if (!strings_equal(curr.getBanner(), p.getBanner())) {
		banner = p.getBanner();
		banner_req_changed = true;
	}

	if (!arrays_equal(curr.getFileContents(), p.getFileContents()))
		file_contents = p.getFileContents();

	if (!arrays_equal(curr.getUserAllowList(), p.getUserAllowList())) {
		allow_changed = true;
		// If the current value is "none" and the new
		// value is null nothing is changing.
		String[] arr = curr.getUserAllowList();
		if ((arr != null) && (arr.length != 0)) {
			if (arr[0].equals("none")) {
				if (p.getUserAllowList() == null) {
					allow_changed = false;
				}
			}
		}
	}
	if (!arrays_equal(curr.getUserDenyList(), p.getUserDenyList())) {
		allow_changed = true;
	}
	if (allow_changed) {
		user_allow_list = p.getUserAllowList();
		user_deny_list = p.getUserDenyList();
	}

	//
	// Return if nothing changed.
	//
	if ((printertype == null) &&
	    (comment == null) &&
	    (device == null) &&
	    (notify == null) &&
	    (protocol == null) &&
	    (destination == null) &&
	    (make == null) &&
	    (model == null) &&
	    (ppd == null) &&
	    (file_contents == null) &&
	    (!allow_changed) &&
	    (!default_printer_changed) &&
	    (!enable_changed) &&
	    (!accept_changed) &&
	    (!banner_req_changed)) {
		return;
	}

	// If this is the default printer set it.
	if (default_printer_changed) {
		if (default_printer) {
			cmd = "/usr/sbin/lpadmin -d " + printername;
		} else {
			cmd = "/usr/sbin/lpadmin -x _default";
		}
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	//
	// If this is only a default printer change then possibly
	// update the name service and return.
	if ((printertype == null) &&
	    (comment == null) &&
	    (device == null) &&
	    (notify == null) &&
	    (protocol == null) &&
	    (destination == null) &&
	    (make == null) &&
	    (model == null) &&
	    (ppd == null) &&
	    (file_contents == null) &&
	    (!allow_changed) &&
	    (!enable_changed) &&
	    (!accept_changed) &&
	    (!banner_req_changed)) {
		if (nameservice.equals("system")) {
			return;
		}
		p.modhints = "defaultonly";

		DoPrinterNS.set("modify", p, ns);
		p.modhints = "";
		return;
	}

	//
	// Do enable/accept
	//
	if (enable_changed) {
		if (p.getEnable() == true) {
			cmd = "/usr/bin/enable " + printername;
		} else {
			cmd = "/usr/bin/disable " + printername;
		}
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}
	if (accept_changed) {
		if (p.getAccept() == true) {
			cmd = "/usr/sbin/accept " + printername;
		} else {
			cmd = "/usr/sbin/reject " + printername;
		}
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}


	//
	// Do some slight of hand to deal with overloading of destination
	// with device for uri protocol
	// Done at the last moment to prevent modifying logic for old/new
	// properties of the queue

	if (isURI) {
		if (destination != null)
			device = destination;
		else
			device = curr.getDestination();
		destination = null;
		protocol = null;
	} else {
		if (protocol != null) {
			device = "/dev/null";
		}
	}



	//
	// Build the modify command
	//

	cmd = "/usr/sbin/lpadmin -p " + printername;

	if (printername != null)
		if (DoPrinterUtil.isLocalhost(printername)) {
			cmd = cmd.concat(" -s localhost");
			Debug.message("SVR:DoModifyPrinter:isLocalhost:true");
	}

	if (device != null) {
		cmd = cmd.concat(" -v " + device);
	}

	// Network printer
	if (isURI) {
                cmd = cmd.concat(" -m uri");

	} else if (protocol != null) {

		if (curr.getPPD() != null)
               		cmd = cmd.concat(" -m netstandard_foomatic");
		else
               		cmd = cmd.concat(" -m netstandard");
	}

	if (printertype != null)
		cmd = cmd.concat(" -T " + printertype);

	if (ppd != null) {
		ppdfile = new String(DoPrinterUtil.getPPDFile(make,
				model, ppd));

	Debug.message("SVR:modifyLocal:ppdfile: " + ppdfile);

		cmd = cmd.concat(" -n " + ppdfile);
	}

	if (notify != null)
		cmd = cmd.concat(" -A " + notify);

	// destination is overloaded to hold uri device for network printers
	// if the protocol is uri, don't set either destination or protocol
	// the device has been set to the destination above

	if (isURI) {
			cmd = cmd.concat(" -o dest=");
			cmd = cmd.concat(" -o protocol=");
	} else {
		if (destination != null)
		    cmd = cmd.concat(" -o dest=" + destination);
		if (protocol != null)
		    cmd = cmd.concat(" -o protocol=" + protocol);
	}

	if ((file_contents != null) && (file_contents.length != 0)) {
		String tmpstr = file_contents[0];
		for (int i = 1; i < file_contents.length; i++) {
			tmpstr = tmpstr.concat("," + file_contents[i]);
		}
		cmd = cmd.concat(" -I " + tmpstr);
	}

	if (banner_req_changed) {
		if (banner != null) {
			cmd = cmd.concat(" -o banner=" + banner);
		}
	}

	//
	// Has any of the above changed.
	//
	if (!cmd.equals("/usr/sbin/lpadmin -p " + printername)) {
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
	}

	//
	// If the user allow list changed delete all then re-add
	//
	if (allow_changed) {
		cmd = "/usr/sbin/lpadmin -p " + printername +
			" -u allow:none";
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;

		if ((user_deny_list != null) &&
		    (user_deny_list.length != 0)) {
			String tmpstr = user_deny_list[0];
			for (int i = 1; i < user_deny_list.length; i++) {
				tmpstr = tmpstr.concat(","
				    + user_deny_list[i]);
			}
			cmd = "/usr/sbin/lpadmin -p " + printername +
			    " -u deny:" + tmpstr;
			p.setCmdLog(cmd);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else if (err != null) {
				p.setWarnLog(err);
			}
			syscmd = null;
		}

		if ((user_allow_list != null) &&
		    (user_allow_list.length != 0) &&
		    (!user_allow_list[0].equals("none"))) {
			String tmpstr = user_allow_list[0];
			for (int i = 1; i < user_allow_list.length; i++) {
				tmpstr = tmpstr.concat(","
				    + user_allow_list[i]);
			}
			cmd = "/usr/sbin/lpadmin -p " + printername +
			    " -u allow:" + tmpstr;
			p.setCmdLog(cmd);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else if (err != null) {
				p.setWarnLog(err);
			}
			syscmd = null;
		}
	}

	if (comment != null) {
		//
		// Have to use a command array here since
		// exec(String) doesn't parse quoted strings.
		// Use lpadmin so the comment in /etc/printers.conf
		// and /etc/lp/printers/comment stay in sync.
		//
		String cmd_array[] =
			{ "/usr/sbin/lpadmin", "-D",
				comment, "-p", printername };
		cmd = "/usr/sbin/lpadmin -D " +
			"\"" + comment + "\"" + " -p " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd_array);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else if (err != null) {
			p.setWarnLog(err);
		}
		syscmd = null;
		if (comment.equals("")) {
			//
			// LPADMIN BUG. Comment not cleared in printers.conf
			// so force it with lpset.
			//
			cmd = "/usr/bin/lpset -a description= " + printername;
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			if (syscmd.getExitValue() != 0) {
				err = syscmd.getError();
				p.setWarnLog(err);
			}
			syscmd = null;
		}
	}

	//
	// Return if we don't need to touch the name service.
	//
	if (nameservice.equals("system")) {
		return;
	}
	if ((comment == null) && (!default_printer_changed)) {
		return;
	}

	DoPrinterNS.set("modify", p, ns);
	return;
    }

    //
    // Do the work of modifying a remote printer.
    //
    private static void modifyRemote(
	Printer p,
	Printer curr,
	NameService ns) throws Exception
    {
	int exitvalue = 0;
	String err = null;
	String cmd = null;
	String cmd_array[] = new String[4];
	SysCommand syscmd = null;

        String printername = null;
        String printserver = null;
        String comment = null;
	String extensions = null;
        boolean default_printer = false;
	boolean default_printer_changed = false;

        String nameservice = ns.getNameService();

	printername = p.getPrinterName();
	if (!strings_equal(curr.getPrintServer(), p.getPrintServer()))
		printserver = p.getPrintServer();

	if (!strings_equal(curr.getComment(), p.getComment())) {
		comment = p.getComment();
		if (comment == null) {
			// The comment changed to empty.
			p.setComment("");
			comment = "";
		}
	}
//
// Don't support extensions in the gui yet.
// If they exist leave them alone.
// EXTENSIONS
	p.setExtensions(curr.getExtensions());
	if (!strings_equal(curr.getExtensions(), p.getExtensions()))
		extensions = p.getExtensions();
	if (curr.getIsDefaultPrinter() != p.getIsDefaultPrinter()) {
		default_printer = p.getIsDefaultPrinter();
		default_printer_changed = true;
	}

	//
	// Return if nothing changed.
	//
	if ((printserver == null) &&
	    (extensions == null) &&
	    (comment == null) &&
	    (!default_printer_changed)) {
		return;
	}

	//
	// If this is only a default printer change then set modhints
	//
	if ((printserver == null) &&
	    (extensions == null) &&
	    (comment == null)) {
		p.modhints = "defaultonly";
	}


        //
        // Find out if we are the nis master
        //
        boolean isnismaster = false;
	if (nameservice.equals("nis")) {
        	String nshost = ns.getNameServiceHost();
        	Host h = new Host();
        	String lh = h.getLocalHostName();
        	if (lh.equals(nshost))
                	isnismaster = true;
		h = null;
	}

	//
	// If we are not updating system and we are not the nis
	// master then update the name service and return.
	//
	if ((!nameservice.equals("system")) && (!isnismaster)) {
		DoPrinterNS.set("modify", p, ns);
		p.modhints = "";
		return;
	}
	p.modhints = "";

	//
	// Take care of the bsdaddr attribute
	//
	// EXTENSIONS
	// The gui doesn't support extensions yet so the goal
	// here is to prepare for it but don't actually
	// modify them.
	//
	if ((printserver != null) || (extensions != null)) {
		// If printserver is null we are changing
		// extensions. Set printserver to its current
		// value.
		if (printserver == null) {
			printserver = curr.getPrintServer();
		}
		String bsdaddr = "bsdaddr=" + printserver + ","
			+ printername;
		//
		// Leave the extensions alone
		// EXTENSIONS
		//
		extensions = curr.getExtensions();
		if (extensions != null) {
			bsdaddr = bsdaddr.concat("," + extensions);
		}
		cmd = "/usr/bin/lpset -a " + bsdaddr + " " + printername;
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
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
	}
	if (comment != null) {
		cmd = "/usr/bin/lpset" + " -a description=" +
			"\"" + comment + "\"" +
			" " + printername;
		cmd_array[0] = "/usr/bin/lpset";
		cmd_array[1] = "-a";
		cmd_array[2] = "description=" + comment;
		cmd_array[3] = printername;

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
	}

	// If this is the default printer set it.
	if (default_printer_changed) {
		if (default_printer) {
			cmd = "/usr/sbin/lpadmin -d " + printername;
		} else {
			cmd = "/usr/sbin/lpadmin -x _default";
		}
		p.setCmdLog(cmd);
		syscmd = new SysCommand();
		syscmd.exec(cmd);
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
	}

	//
	// If it's nis and we are here then we are the nis
	// master. This call will do the make for us.
	//
	if (nameservice.equals("nis")) {
		DoPrinterNS.set("modify", p, ns);
	}
	return;
    }

    private static boolean arrays_equal(String[] arr1, String[] arr2)
    {
	if ((arr1 == null) && (arr2 == null)) {
		return (true);
	}
	if ((arr1 == null) || (arr2 == null)) {
		return (false);
	}
	if (arr1.length != arr2.length) {
		return (false);
	}

	int i, j;
	String str;
	boolean found;
	for (i = 0; i < arr1.length; i++) {
		found = false;
		str = arr1[i];
		for (j = 0; j < arr2.length; j++) {
			if (str.equals(arr2[j])) {
				found = true;
			}
		}
		if (found == false) {
			return (false);
		}
	}
	return (true);
    }

    private static boolean strings_equal(String str1, String str2)
    {
	if ((str1 == null) && (str2 == null)) {
		return (true);
	}
	if ((str1 == null) || (str2 == null)) {
		return (false);
	}

	return (str1.equals(str2));
    }
}
