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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DoPrinterView class
 * Worker class for gathering printer information.
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

import com.sun.admin.pm.client.pmNeedPPDCacheException;
import com.sun.admin.pm.client.pmCacheMissingPPDException;
// import com.sun.admin.pm.client.pmGuiException;

public class DoPrinterView {

    public static void main(String[] args) {
	Debug.setDebugLevel(Debug.ALL);

	Printer p = new Printer();
	p.setPrinterName("petite");
	NameService ns = new NameService();

	try {
		view(p, ns);
	}
	catch (Exception e)
	{
		System.out.println(e);
		System.exit(1);
	}
	PrinterDebug.printObj(p);

	System.out.println("Commands:\n" + p.getCmdLog());
	System.out.println("Errors:\n" + p.getErrorLog());
	System.out.println("Warnings:\n" + p.getWarnLog());
	System.exit(0);
    }

    //
    // Interface to Printer object.
    //
    public static void view(
	Printer p,
	NameService ns) throws Exception
    {
	boolean islocal =
		DoPrinterUtil.isLocal(p.getPrinterName());
	if (islocal) {
		viewLocal(p, ns);
	} else {
		viewRemote(p, ns);
	}

	return;
    }

    //
    // Do the work getting Remote printer attributes.
    //
    private static void viewRemote(
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterView.viewRemote()");

	int exitvalue = 0;
	int i, j;
	String o = null;
	String printername = p.getPrinterName();
	String printserver = null;
	String comment = null;
	String extensions = null;
	boolean default_printer = false;

	String nsarg = ns.getNameService();

	String err = null;

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/lpget -n " + nsarg + " " +
		printername, "LC_ALL=C");

	if (syscmd.getExitValue() != 0) {
		err = syscmd.getError();
		p.setErrorLog(err);
		// Add stdout since thats where lpget sends errors.
		err = syscmd.getOutput();
		p.setErrorLog(err);
		syscmd = null;
		throw new pmCmdFailedException(err);
	}
	o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		throw new pmCmdFailedException(err);
	}
	// For easier parsing.
	o = o.concat("\n");

	i = o.indexOf("bsdaddr=");
	if (i == -1) {
		Debug.message("SVR: Can't parse bsdaddr for " + printername);
		throw new pmException();
	}
	i = i + 8;
	j = o.indexOf(",", i);
	if (j == -1) {
		Debug.message("SVR: Can't parse bsdaddr for " + printername);
		throw new pmException();
	}
	printserver = o.substring(i, j);

	i = o.indexOf(",Solaris");
	if (i != -1) {
		extensions = "Solaris";
	}

	i = o.indexOf("description=");
	if (i != -1) {
		i = i + 12;
		j = o.indexOf("\n", i);
		if (j != -1) {
			comment = o.substring(i, j);
		}
	}

	String def = DoPrinterUtil.getDefault(nsarg);
	if ((def != null) && (def.equals(printername))) {
		default_printer = true;
	}
	p.setPrintServer(printserver);
	p.setExtensions(extensions);
	p.setComment(comment);
	p.setIsDefaultPrinter(default_printer);
	return;
    }

    //
    // Do the work getting printer attributes.
    //
    private static void viewLocal(
	Printer p, NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterView.viewLocal()");

	int i = -1;
	int exitvalue = 0;
	String str = null;
	String o = null;

	String printername = p.getPrinterName();
	String printertype = null;
	String printserver = null;
	String comment = null;
	String device = null;
	String make = null;
	String model = null;
	String ppd = null;
	String notify = null;
	String protocol = null;
	String destination = null;
	String extensions = "Solaris";
	String[] file_contents = null;
	String[] user_allow_list = null;
	String[] user_deny_list = null;
	boolean default_printer = false;
	String banner = null;
	boolean enable = false;
	boolean accept = false;

	String ppdfile = null;

	String def = DoPrinterUtil.getDefault("system");
	if ((def != null) && (def.equals(printername))) {
		default_printer = true;
	}

	//
	// Parse lpstat output
	//
	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/lpstat -L -l -a " +
		printername + " -p " + printername, "LC_ALL=C");

	if (syscmd.getExitValue() != 0) {
		String err = syscmd.getError();
		p.setErrorLog(err);
		syscmd = null;
		throw new pmCmdFailedException(err);
	}

	o = syscmd.getOutput();
	syscmd = null;

	// Append a newline to make parsing easier.
	o = o.concat("\n");

	comment = getToken(o, "\tDescription:");
	if (comment.equals("")) {
		comment = null;
	}

	// Get the PPD path/filename from lpstat
	// Get the make/model/ppd nickname using ppd-filename
	ppdfile = getToken(o, "\tPPD:");
	if ((ppdfile == null) || (ppdfile.equals("none")) ||
					(ppdfile.equals(""))) {
		ppdfile = null;
	} else {
	// Set the make/model/ppd

	    if (!pmMisc.isppdCachefile()) {
		throw new pmNeedPPDCacheException("ppdcache missing");
	    }
		String ret[];
		ret = new String[3];
		ret = DoPrinterUtil.getMakeModelNick(ppdfile);

		if ((ret != null) && (!ret.equals(""))) {
			make = ret[0];
			model = ret[1];
			ppd = ret[2];
		} else {
			throw new pmCacheMissingPPDException(
					"PPD file not in cache");
		}
	}

	int j = -1;
	printserver = p.getPrintServer();

	printertype = getToken(o, "Printer types:");
	i = o.indexOf("enabled since");
	if (i != -1) {
		enable = true;
	}
	i = o.indexOf("not accepting requests");
	if (i == -1) {
		accept = true;
	}

	i = o.indexOf("Banner not required");
	if (i != -1) {
		banner = "optional";
	}
	i = o.indexOf("Banner required");
	if (i != -1) {
		banner = "always";
	}
	i = o.indexOf("Banner page never printed");
	if (i != -1) {
		banner = "never";
	}



	// If we have Options then look for destination and protocol.
	protocol = "bsd";
	str = "Options:";
	i = o.indexOf(str);
	if (i != -1) {
		// Set str to the substring containing only the options line.
		j = o.indexOf("\n", i);
		str = o.substring(i, j);

		// Append a comma to make parsing easier.
		str = str.concat(",");
		i = str.indexOf("dest=");
		if (i != -1) {
			i += 5;
			j = str.indexOf(",", i);
			destination = str.substring(i, j);
			destination = destination.trim();
		}
		i = str.indexOf("protocol=");
		if (i != -1) {
			i += 9;
			j = str.indexOf(",", i);
			protocol = str.substring(i, j);
			protocol = protocol.trim();
		}
	}

	StringTokenizer st;

	// Build array of content types.
	str = getToken(o, "Content types:");
	if (str != null) {
		str = str.replace(',', ' ');
		st = new StringTokenizer(str);
		if (st.countTokens() != 0) {
			file_contents = new String[st.countTokens()];
			for (i = 0; st.hasMoreTokens(); i++) {
				file_contents[i] = st.nextToken();
			}
		}
	}

	//
	// User allow list.
	//
	str = "Users allowed:\n";
	i = o.indexOf(str);
	if (i != -1) {
		i += str.length();
		// Grab the substring containing only users.
		j = o.indexOf("\tForms");
		if (j != -1) {
			str = o.substring(i, j);
			st = new StringTokenizer(str);
			if (st.countTokens() != 0) {
				user_allow_list = new String[st.countTokens()];
				for (i = 0; st.hasMoreTokens(); i++) {
					user_allow_list[i] = st.nextToken();
				}
			}
		}
	}
	if (user_allow_list == null) {
	} else if (user_allow_list[0].equals("(all)")) {
		user_allow_list[0] = "all";
	} else if (user_allow_list[0].equals("(none)")) {
		user_allow_list[0] = "none";
	}
	//
	// User deny list
	//
	syscmd = new SysCommand();
	String cmd = "/bin/cat /etc/lp/printers/" + printername + "/users.deny";
	syscmd.exec(cmd);
	if (syscmd.getExitValue() == 0) {
		str = syscmd.getOutput();
		if ((str != null) && (str.length() != 0)) {
			st = new StringTokenizer(str);
			if (st.countTokens() != 0) {
				user_deny_list = new String[st.countTokens()];
				for (i = 0; st.hasMoreTokens(); i++) {
					user_deny_list[i] = st.nextToken();
				}
			}
		}
	}
	syscmd = null;

	//
	// Get fault action
	//
	str = getToken(o, "On fault:");
	if (str != null) {
		if (!str.equals("")) {
			if (str.indexOf("write") != -1) {
				notify = "write";
			} else if (str.indexOf("mail") != -1) {
				notify = "mail";
			} else if (str.indexOf("no alert") != -1) {
				notify = "none";
			} else if (str.indexOf("alert with") != -1) {
				i = str.indexOf("\"");
				if (i != -1) {
					j = str.lastIndexOf("\"");
					if (j > i) {
						notify = str.substring(++i, j);
					}
				}
			} else if (str.indexOf(" quiet ") != -1) {
				notify = "quiet";
			} else {
				notify = "unknown";
			}
		}
	}
	syscmd = null;
	//
	// Get the printers device
	//
	syscmd = new SysCommand();
	syscmd.exec("/usr/bin/lpstat -L -v " + printername,
	    "LC_ALL=C");

	o = syscmd.getOutput();
	if (o != null) {
		o = o.concat("\n");
		device = getToken(o, ":");
	}

	Debug.message("SVR: DEVICE (" + device + ")");
	//
	// If the device is in URI form (scheme:// ...), set the protocol
	// for the "network attached" modify screen.
	//
	if (device.indexOf("://") != -1) {
		protocol = "uri";
		destination = device;
		device = null;
	}

	syscmd = null;

	p.setPrinterType(printertype);
	p.setPrintServer(printserver);
	p.setFileContents(file_contents);
	p.setComment(comment);
	p.setDevice(device);
	p.setMake(make);
	p.setModel(model);
	p.setPPD(ppd);
	p.setPPDFile(ppdfile);
	p.setNotify(notify);
	p.setProtocol(protocol);
	p.setDestination(destination);
	p.setExtensions(extensions);
	p.setIsDefaultPrinter(default_printer);
	p.setBanner(banner);
	p.setEnable(enable);
	p.setAccept(accept);
	p.setUserAllowList(user_allow_list);
	p.setUserDenyList(user_deny_list);

	if (ns.getNameService().equals("system"))
		return;
	Debug.message(
	    "SVR: Overlaying name service attributes on local printer");
	try {
		viewRemote(p, ns);
	}
	catch (Exception e)
	{
		Debug.warning(
		    "SVR: Overlay of name service attributes failed.");
		Debug.warning("SVR: " + e.getMessage());
	}
	return;
    }

    //
    // Return substring starting at sub + 1 and ending with
    // a newline.
    //
    public static String getToken(String str, String sub)
    {
	int i = -1;
	int j = -1;
	String result = null;

	i = str.indexOf(sub);
	if (i != -1) {
		if (str.charAt(i + sub.length()) == '\n') {
			return (null);
		}
		i = i + sub.length();
		j = str.indexOf("\n", i);
		if (j != -1) {
			result = str.substring(i, j);
			result = result.trim();
		}
	}
	return (result);
    }
}
