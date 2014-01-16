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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DoPrinterNS class
 * Worker class for updating name services.
 * Interfaces to JNI code.
 */

package com.sun.admin.pm.server;

public class DoPrinterNS
{
    //
    // JNI member functions
    //
    private synchronized static native int dorexec(String nshost,
	String user, String passwd, String cmd, String locale);
    private synchronized static native int updateoldyp(String action,
	String printername, String printserver, String extensions,
	String comment, String isdefault);
    private synchronized static native int updateldap(String action,
	String host, String binddn, String passwd,
	String printername, String printserver, String extensions,
	String comment, String isdefault);
    private synchronized static native String getstderr();
    private synchronized static native String getstdout();

    //
    // Load JNI.
    //
    static
    {
	System.loadLibrary("pmgr");
    }

    //
    // main for testing
    //
    public static void main(String[] args) {
	//
	// Set attributes for testing.
	//
	NameService ns = null;
	try {
		ns = new NameService("nis");
	}
	catch (Exception e) {
		System.out.println(e);
		System.exit(1);
	}
	ns.setPasswd("");

	Printer p = new Printer(ns);
	p.setPrinterName("javatest");
	p.setPrintServer("zelkova");
	p.setComment("This is a comment");
	p.setIsDefaultPrinter(false);
	p.setLocale(null);

	String action = "add";
	if (args.length >= 1)
		action = args[0];
	try {
		set(action, p, ns);
	}
	catch (Exception e) {
		System.out.println(e);
	}
	System.out.println("Commands:\n" + p.getCmdLog());
	System.out.println("Errors:\n" + p.getErrorLog());
	System.out.println("Warnings:\n" + p.getWarnLog());
	System.exit(0);
    }

    //
    // Interface to DoPrinter[add|mod|delete]
    //
    public static void set(
	String action,
	Printer p,
	NameService ns) throws Exception
    {
	String nameservice = ns.getNameService();

	if (nameservice.equals("system")) {
		return;
	} else if (nameservice.equals("nis")) {
		setNIS(action, p, ns);
		return;
	}
	setNS(action, p, ns);
	return;
    }

    private static void setNIS(
	String action,
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterNS.setNIS(): " + action);

	String printername = p.getPrinterName();
	String printserver = p.getPrintServer();
	String comment = p.getComment();
	String extensions = p.getExtensions();
	boolean default_printer = p.getIsDefaultPrinter();
	String locale = p.getLocale();
	if (locale == null)
		locale = "C";

	String nameservice = ns.getNameService();
	String nshost = ns.getNameServiceHost();
	String user = ns.getUser();
	String passwd = ns.getPasswd();

	String cmd = null;
	String err = null;
	int ret = 0;
	int exitvalue = 0;

	//
	// If this is the nis master we only need to do the make
	// locally.
	//
	Host h = new Host();
	String lh = h.getLocalHostName();
	if (lh.equals(nshost)) {
		cmd = "/usr/ccs/bin/make -f /var/yp/Makefile";
		cmd = cmd.concat(" -f /usr/lib/print/Makefile.yp ");
		cmd = cmd.concat("printers.conf");

		p.setCmdLog(cmd);
		SysCommand syscmd = new SysCommand();
		syscmd.exec(cmd);

		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			p.setErrorLog(err);
			syscmd = null;
			throw new pmCmdFailedException(err);
		} else {
			// ignore touch warning
			// p.setWarnLog(err);
		}
		syscmd = null;
		return;
	}

	String cmdprefix = "rexec(" + nshost + "): ";

	cmd = "/usr/bin/echo";
	Debug.message("SVR: " + cmdprefix + cmd);
	ret = dorexec(nshost, user, passwd, cmd, locale);
	if (ret != 0) {
		throw new pmAuthException(getstderr());
	}
	//
	// Do we have lpset
	//
	cmd = "/usr/bin/ls /usr/bin/lpset";
	Debug.message("SVR: " + cmdprefix + cmd);
	ret = dorexec(nshost, user, passwd, cmd, locale);
	if (ret != 0) {
		throw new pmCmdFailedException(getstderr());
	}
	String tmpstr = getstdout();
	tmpstr = tmpstr.trim();
	if (!tmpstr.equals("/usr/bin/lpset")) {
		Debug.message("SVR: No lpset found. Checking rhosts.");

		// Are we set up in rhosts?
		cmd = "rsh ";
		cmd = cmd.concat(nshost);
		cmd = cmd.concat(" echo");

		SysCommand syscmd = new SysCommand();
		syscmd.exec(cmd);
		err = syscmd.getError();
		if (syscmd.getExitValue() != 0) {
			syscmd = null;
			throw new pmAuthRhostException(err);
		}
		syscmd = null;
		//
		// We don't have lpset. Must be pre-2.6 master.
		// We are set up in rhosts so use libprint
		// to update it.
		//
		p.setCmdLog("rsh " + nshost + "...");
		String def = "false";
		if (default_printer)
			def = "true";

		Debug.message("SVR: updateoldyp(): ");
		Debug.message("SVR: action=" + action);
		Debug.message("SVR: printername=" + printername);
		Debug.message("SVR: printserver=" + printserver);
		Debug.message("SVR: extensions=" + extensions);
		Debug.message("SVR: comment=" + comment);
		Debug.message("SVR: default=" + def);

		ret = updateoldyp(action, printername,
			printserver, extensions, comment, def);
		if (ret != 0) {
			throw new pmCmdFailedException("libprint");
		}
		return;
	}

	//
	// Add and modify are the same
	//
	boolean domake = false;
	if (!action.equals("delete")) {
		//
		// If we are here from a modify and only need
		// to change the default printer ...
		//
		if (!p.modhints.equals("defaultonly")) {
			String bsdaddr = "bsdaddr=" + printserver + "," +
			    printername;
			if (extensions != null) {
				bsdaddr = bsdaddr.concat("," + extensions);
			}
			cmd = "/usr/bin/lpset -a " + bsdaddr;
			if (comment != null) {
			    cmd = cmd.concat(" -a " + "description=" +
			    "\"" + comment + "\"");
			}
			cmd = cmd.concat(" " + printername);

			Debug.message("SVR: " + cmdprefix + cmd);
			p.setCmdLog(cmdprefix + cmd);
			ret = dorexec(nshost, user, passwd, cmd, locale);
			err = getstderr();
			if (ret != 0) {
				p.setErrorLog(err);
				throw new pmCmdFailedException(err);
			}
			if (!err.equals("")) {
				p.setWarnLog(err);
			}
			domake = true;
		}

		cmd = null;
		String def = DoPrinterUtil.getDefault("nis");
		if (default_printer) {
			if (!printername.equals(def)) {
				cmd = "/usr/bin/lpset -a " + "use=" +
				    printername + " _default";
			}
		} else {
			if ((def != null) && (def.equals(printername))) {
				//
				// It was the default but not any more.
				//
				cmd = "/usr/bin/lpset -x _default";
			}
		}
		if (cmd != null) {
			Debug.message("SVR: " + cmdprefix + cmd);
			p.setCmdLog(cmdprefix + cmd);
			ret = dorexec(nshost, user, passwd, cmd, locale);
			err = getstderr();
			if (ret != 0) {
				p.setErrorLog(err);
				throw new pmCmdFailedException(err);
			}
			if (!err.equals("")) {
				p.setWarnLog(err);
			}
			domake = true;
		}
	} else {
		if (DoPrinterUtil.exists(printername, "nis")) {
			// delete
			cmd = "/usr/bin/lpset -x " + printername;
			Debug.message("SVR: " + cmdprefix + cmd);
			p.setCmdLog(cmdprefix + cmd);
			ret = dorexec(nshost, user, passwd, cmd, locale);
			err = getstderr();
			if (ret != 0) {
				p.setErrorLog(err);
				throw new pmCmdFailedException(err);
			}
			if (!err.equals("")) {
				p.setWarnLog(err);
			}
			domake = true;
		}
		String def = DoPrinterUtil.getDefault("nis");
		if ((def != null) && (def.equals(printername))) {
			cmd = "/usr/bin/lpset -x _default";
			Debug.message("SVR: " + cmdprefix + cmd);
			p.setCmdLog(cmdprefix + cmd);
			ret = dorexec(nshost, user, passwd, cmd, locale);
			err = getstderr();
			if (ret != 0) {
				p.setErrorLog(err);
				throw new pmCmdFailedException(err);
			}
			if (!err.equals("")) {
				p.setWarnLog(err);
			}
			domake = true;
		}
	}
	if (!domake) {
		return;
	}

	cmd = "cd /var/yp; /usr/ccs/bin/make -f /var/yp/Makefile";
	cmd = cmd.concat(" -f /usr/lib/print/Makefile.yp printers.conf");
	Debug.message("SVR: " + cmdprefix + cmd);
	p.setCmdLog(cmdprefix + cmd);
	ret = dorexec(nshost, user, passwd, cmd, locale);
	err = getstderr();
	if (ret != 0) {
		p.setErrorLog(err);
		throw new pmCmdFailedException(err);
	}
	if (!err.equals("")) {
		p.setWarnLog(err);
	}
	return;
    }

    private static void setNS(
	String action,
	Printer p,
	NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterNS.setNS(): " + action);

	String printername = p.getPrinterName();
	String printserver = p.getPrintServer();
	String extensions = p.getExtensions();
	String comment = p.getComment();
	boolean default_printer = p.getIsDefaultPrinter();

	String nameservice = ns.getNameService();

	String nshost = ns.getNameServiceHost();
	String user = ns.getUser();
	String passwd = ns.getPasswd();

	int exitvalue;
	SysCommand syscmd = null;
	String err;
	String cmd = null;
	String cmd_log = null;
	String cmd_array[] = new String[14];

	int index = 0;
	String base_cmd = "/usr/bin/lpset -n " + nameservice;
	String base_cmd_log = "/usr/bin/lpset -n " + nameservice;

	cmd_array[index++] = "/usr/bin/lpset";
	cmd_array[index++] = "-n";
	cmd_array[index++] = nameservice;

	/*
	 * Use jni to update ldap since the passwd is sensitive.
	 */
	if (nameservice.equals("ldap")) {

		if ((nshost == null) || (nshost.equals(""))) {
			throw new pmInternalErrorException(
			    "Missing LDAP host for ldap operation");
		}
		if ((user == null) && (user.equals(""))) {
			throw new pmInternalErrorException(
			    "Missing Binddn for ldap operation");
		}
		if ((passwd == null) && (passwd.equals(""))) {
			throw new pmInternalErrorException(
			    "Missing passwd for ldap operation");
		}

		p.setCmdLog("ldap ...");

		String def = "false";
		if (default_printer)
			def = "true";

		Debug.message("SVR: updateldap(): ");
		Debug.message("SVR: action=" + action);
		Debug.message("SVR: host=" + nshost);
		Debug.message("SVR: binddn=" + user);
		Debug.message("SVR: passwd=****");
		Debug.message("SVR: printername=" + printername);
		Debug.message("SVR: printserver=" + printserver);
		Debug.message("SVR: extensions=" + extensions);
		Debug.message("SVR: comment=" + comment);
		Debug.message("SVR: default=" + def);

		exitvalue = updateldap(action, nshost, user, passwd,
		    printername, printserver, extensions, comment,
		    def);

		if (exitvalue != 0) {
			throw new pmCmdFailedException("libprint");
		}
		return;
	}

	//
	// Add and modify are the same
	//
	if (!action.equals("delete")) {
		//
		// If we are here for a modify and we're only setting
		// the default printer ...
		//
		if (!p.modhints.equals("defaultonly")) {
			String bsdaddr = "bsdaddr=" + printserver + "," +
			    printername;
			if (extensions != null) {
				bsdaddr = bsdaddr.concat("," + extensions);
			}
			cmd_array[index++] = "-a";
			cmd_array[index++] = bsdaddr;
			cmd_log = base_cmd_log + " -a " + bsdaddr;
			if (comment != null) {
				cmd_array[index++] = "-a";
				cmd_array[index++] = "description=" + comment;
				cmd_log = cmd_log.concat(" -a " +
					"description=" + "\"" + comment + "\"");
			}
			cmd_array[index++] = printername;
			cmd_log = cmd_log.concat(" " + printername);

			p.setCmdLog(cmd_log);
			syscmd = new SysCommand();
			syscmd.exec(cmd_array);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else {
				p.setWarnLog(err);
			}
			syscmd = null;
		}
		cmd = null;
		cmd_log = null;
		String args = null;
		String def = DoPrinterUtil.getDefault(nameservice);
		if (default_printer) {
			if (!printername.equals(def)) {
				args = " -a " + "use=" + printername +
				    " _default";
				cmd = base_cmd + args;
				cmd_log = base_cmd_log + args;
			}
		} else {
			if ((def != null) && (def.equals(printername))) {
				//
				// It was the default but not any more.
				//
				args = " -x _default";
				cmd = base_cmd + args;
				cmd_log = base_cmd_log + args;
			}
		}
		if (cmd != null) {
			p.setCmdLog(cmd_log);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else {
				p.setWarnLog(err);
			}
			syscmd = null;
		}
	} else {
		if (DoPrinterUtil.exists(printername, nameservice)) {
			// delete
			cmd = base_cmd + " -x " + printername;
			cmd_log = base_cmd_log + " -x " + printername;
			p.setCmdLog(cmd_log);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else {
				p.setWarnLog(err);
			}
			syscmd = null;

		}
		String def = DoPrinterUtil.getDefault(nameservice);
		if ((def != null) && (def.equals(printername))) {
			cmd = base_cmd + " -x _default";
			cmd_log = base_cmd_log + " -x _default";
			p.setCmdLog(cmd_log);
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			err = syscmd.getError();
			if (syscmd.getExitValue() != 0) {
				p.setErrorLog(err);
				syscmd = null;
				throw new pmCmdFailedException(err);
			} else {
				p.setWarnLog(err);
			}
			syscmd = null;
		}
	}
	return;
    }

    public static boolean doAuth(NameService ns) throws Exception
    {
	Debug.message("SVR: DoPrinterNS.checkAuth()");

	String nsname = ns.getNameService();
	String host = ns.getNameServiceHost();
	String user = ns.getUser();
	String passwd = ns.getPasswd();

	if (nsname.equals("system")) {
		if (!isRoot()) {
			Debug.error(
			    "SVR: User does not have root priveleges.");
			throw new pmAuthException();
		}
	} else if (nsname.equals("nis")) {
		Host h = new Host();
		String lh = h.getLocalHostName();
		String nm = h.getNisHost("master");
		if (lh.equals(nm)) {
			// Since we are on the NIS master the
			// check is the same as for "system".
			Debug.message("SVR: Host is NIS master.");
			if (!isRoot()) {
				Debug.error(
				    "SVR: User does not have root access.");
				throw new pmAuthException();
			}
		}
		int ret = dorexec(host, user, passwd, "/usr/bin/echo", "C");
		if (ret != 0) {
			Debug.error(
			    "SVR: User does not have NIS update access.");
			throw new pmAuthException(getstderr());
		}
	} else if (nsname.equals("ldap")) {
		int ret = updateldap("add", host, user, passwd,
		    "_pmTestAuthToken", null, null, null, "false");

		if (ret != 0) {
			Debug.error(
			    "SVR: User does not have LDAP update priveleges.");
			throw new pmAuthException();
		}
		ret = updateldap("delete", host, user, passwd,
		    "_pmTestAuthToken", null, null, null, "false");

	} else {
		throw new pmInternalErrorException(
			"doAuth(): Invalid name service: " + nsname);
	}
	return (true);
    }

    public static void doCheckRootPasswd(String p)
	throws Exception
    {
	Host h = new Host();
	String lh = h.getLocalHostName();

	int ret = dorexec(lh, "root", p, "/usr/bin/echo", "C");
	if (ret != 0) {
		throw new pmAuthException(getstderr());
	}
	return;
    }

    public static boolean isRoot()
	throws Exception
    {
	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/id", "LC_ALL=C");

	String o = syscmd.getOutput();

	if (o == null) {
		throw new pmCmdFailedException(syscmd.getError());
	}
	if (o.indexOf("uid=0(") == -1) {
		return (false);
	}
	return (true);
    }
}
