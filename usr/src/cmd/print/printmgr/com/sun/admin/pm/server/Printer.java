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
 * Printer class
 * Printer object containing attributes and methods for
 * updating printers.
 */

package com.sun.admin.pm.server;

public class Printer
{
    //
    // Printer object attributes
    //
    private String printername = null;
    private String printertype = null;
    private String printserver = null;
    private String comment = null;
    private String device = null;
    private String make = null;
    private String model = null;
    private String ppd = null;
    private String ppdfile = null;
    private String notify = null;
    private String protocol = null;
    private String destination = null;
    private String extensions = null;
    private String[] file_contents = null;
    private String[] user_allow_list = null;
    private String[] user_deny_list = null;
    private boolean use_ppd_file = true;
    private boolean default_printer = false;
    private String banner = null;
    private boolean enable = true;
    private boolean accept = true;

    private String locale = null;	// Possible future use

    private NameService nscontext;

    //
    // Logs
    //
    private String warnlog = null;
    private String errlog = null;
    private String cmdlog = null;

    //
    // Constructors
    //
    public Printer()
    {
	Debug.message("SVR: Printer constructor called empty.");
	nscontext = new NameService();
	PrinterDebug.printObj(nscontext);
    }
    public Printer(NameService ns)
    {
	Debug.message("SVR: Printer constructor called with NS.");
	nscontext = ns;
	PrinterDebug.printObj(ns);
    }

    //
    // Is a printer local to this machine
    //
    public synchronized boolean isPrinterLocal(String printername)
	throws Exception
    {
	Debug.message("SVR: Printer.isPrinterLocal()");
	return (DoPrinterUtil.isLocal(printername));
    }

    //
    // Get details of a printer.
    //
    public synchronized void getPrinterDetails()
	throws Exception
    {
	Debug.message("SVR: Printer.getPrinterDetails()");

	if (printername == null) {
		throw new pmInternalErrorException(
		    "Printer.getPrinterDetails(): printername must be set");
	}
	DoPrinterView.view(this, nscontext);
    }

    //
    // Add a local printer
    //
    public synchronized void addLocalPrinter()
	throws Exception
    {
	Debug.message("SVR: Printer.addLocalPrinter()");

	if (printername == null) {
		throw new pmInternalErrorException(
		    "Printer.addLocalPrinter(): printername must be set");
	}
	if (printserver == null) {
		Host h = new Host();
		printserver = h.getLocalHostName();
		h = null;
	}
	if (device == null) {
		throw new pmInternalErrorException(
		    "Printer.addLocalPrinter(): device must be set");
	}
	if ((pmMisc.isppdCachefile()) && use_ppd_file) {
	    if (make == null) {
		throw new pmInternalErrorException(
			"Printer.addLocalPrinter(): make must be set");
	    }
	    if (model == null) {
		throw new pmInternalErrorException(
			"Printer.addLocalPrinter(): model must be set");
	    }
	    if (ppd == null) {
		throw new pmInternalErrorException(
		"Printer.addLocalPrinter(): ppd file must be selected");
	    }
	}


	PrinterDebug.printObj(this);

	clearLogs();
	DoPrinterAdd.add(this, nscontext);
    }

    //
    // Add access to a remote printer
    //
    public synchronized void addRemotePrinter()
	throws Exception
    {
	Debug.message("SVR: Printer.addRemotePrinter()");

	if (printername == null) {
		throw new pmInternalErrorException(
		    "Printer.addRemotePrinter(): printername must be set");
	}
	if (printserver == null) {
		throw new pmInternalErrorException(
		    "Printer.addRemotePrinter(): printserver must be set");
	}
	PrinterDebug.printObj(this);

	clearLogs();
	DoPrinterAdd.add(this, nscontext);
    }

    //
    // Delete a printer
    //
    public synchronized void deletePrinter()
	throws Exception
    {
	Debug.message("SVR: Printer.deletePrinter()");

	if (printername == null) {
		throw new pmInternalErrorException(
		    "Printer.deletePrinter(): printername must be set");
	}
	PrinterDebug.printObj(this);

	clearLogs();
	DoPrinterDelete.delete(this, nscontext);
    }

    //
    // Modify a printer
    //
    public synchronized void modifyPrinter()
	throws Exception
    {
	Debug.message("SVR: Printer.modifyPrinter()");

	if (printername == null) {
		throw new pmInternalErrorException(
		    "Printer.modifyPrinter(): printername must be set");
	}
	PrinterDebug.printObj(this);

	clearLogs();
	DoPrinterMod.modify(this, nscontext);
    }

    //
    // Set list of commands executed
    //
    public synchronized void setCmdLog(String newcmds)
    {
	if (newcmds == null) {
		return;
	}
	if (!newcmds.endsWith("\n")) {
		newcmds = newcmds.concat("\n");
	}
	if (cmdlog == null) {
		cmdlog = new String(newcmds);
		return;
	}
	cmdlog = cmdlog.concat(newcmds);
    }

    //
    // Set an error message.
    //
    public synchronized void setErrorLog(String errs)
    {
	if (errs == null) {
		return;
	}
	if (!errs.endsWith("\n")) {
		errs = errs.concat("\n");
	}
	if (errlog == null) {
		errlog = new String(errs);
		return;
	} else {
		errlog = errlog.concat(errs);
	}
    }

    //
    // Set an warning message.
    //
    public synchronized void setWarnLog(String warning)
    {
	if (warning == null) {
		return;
	}
	if (!warning.endsWith("\n")) {
		warning = warning.concat("\n");
	}
	if (warnlog == null) {
		warnlog = new String(warning);
		return;
	} else {
		warnlog = warnlog.concat(warning);
	}
    }

    //
    // Get commands executed.
    //
    public String getCmdLog()
    {
	if (cmdlog == null) {
		return (null);
	}
	return (new String(cmdlog.trim()));
    }

    //
    // Get error messages
    //
    public String getErrorLog()
    {
	if (errlog == null) {
		return (null);
	}
	return (new String(errlog.trim()));
    }

    //
    // Get warning messages
    //
    public String getWarnLog()
    {
	if (warnlog == null) {
		return (null);
	}
	return (new String(warnlog.trim()));
    }

    //
    // Set printer attributes
    //
    public synchronized void setPrinterName(String arg)
    {
	printername = arg;
    }
    public synchronized void setPrinterType(String arg)
    {
	printertype = arg;
    }
    public synchronized void setPrintServer(String arg)
    {
	printserver = arg;
    }
    public synchronized void setComment(String arg)
    {
	comment = arg;
    }
    public synchronized void setMake(String arg)
    {
	make = arg;
    }
    public synchronized void setModel(String arg)
    {
	model = arg;
    }
    public synchronized void setPPD(String arg)
    {
	ppd = arg;
    }
    public synchronized void setPPDFile(String arg)
    {
	ppdfile = arg;
    }
    public synchronized void setDevice(String arg)
    {
	device = arg;
    }
    public synchronized void setUsePPD(boolean arg)
    {
	use_ppd_file = arg;
    }
    public synchronized void setNotify(String arg)
    {
	notify = arg;
    }
    public synchronized void setProtocol(String arg)
    {
	protocol = arg;
    }
    public synchronized void setDestination(String arg)
    {
	destination = arg;
    }
    public synchronized void setExtensions(String arg)
    {
	extensions = arg;
    }
    public synchronized void setFileContents(String[] arg)
    {
	file_contents = arg;
    }
    public synchronized void setUserAllowList(String[] arg)
    {
	user_allow_list = arg;
    }
    public synchronized void setUserDenyList(String[] arg)
    {
	user_deny_list = arg;
    }
    public synchronized void setIsDefaultPrinter(boolean arg)
    {
	default_printer = arg;
    }
    public synchronized void setBanner(String arg)
    {
	banner = arg;
    }
    public synchronized void setEnable(boolean arg)
    {
	enable = arg;
    }
    public synchronized void setAccept(boolean arg)
    {
	accept = arg;
    }
    public synchronized void setLocale(String arg)
    {
	locale = arg;
    }

    //
    // Get printer attributes.
    //
    public String getPrinterName()
    {
	return (printername);
    }
    public String getPrinterType()
    {
	return (printertype);
    }
    public String getPrintServer()
    {
	return (printserver);
    }
    public String getComment()
    {
	return (comment);
    }
    public String getDevice()
    {
	return (device);
    }
    public boolean getUsePPD()
    {
	return (use_ppd_file);
    }
    public String getMake()
    {
	return (make);
    }
    public String getModel()
    {
	return (model);
    }
    public String getPPD()
    {
	return (ppd);
    }
    public String getPPDFile()
    {
	return (ppdfile);
    }
    public String getNotify()
    {
	return (notify);
    }
    public String getProtocol()
    {
	return (protocol);
    }
    public String getDestination()
    {
	return (destination);
    }
    public String getExtensions()
    {
	return (extensions);
    }
    public String[] getFileContents()
    {
	return (file_contents);
    }
    public String[] getUserAllowList()
    {
	return (user_allow_list);
    }
    public String[] getUserDenyList()
    {
	return (user_deny_list);
    }
    public boolean getIsDefaultPrinter()
    {
	return (default_printer);
    }
    public String getBanner()
    {
	return (banner);
    }
    public boolean getEnable()
    {
	return (enable);
    }
    public boolean getAccept()
    {
	return (accept);
    }
    public String getLocale()
    {
	return (locale);
    }

    protected void clearLogs()
    {
	warnlog = null;
	errlog = null;
	cmdlog = null;
    }

    // Hints for optimizing printer modifications
    protected String modhints = "";
}
