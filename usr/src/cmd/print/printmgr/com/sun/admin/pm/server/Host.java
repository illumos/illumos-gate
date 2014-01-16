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
 * Host class
 * Methods associated with a host.
 */

package com.sun.admin.pm.server;

import java.io.*;

public class Host
{
    public static void main(String[] args)
    {
	try {
		System.out.println(getLocalHostName());
		System.out.println(getDomainName());
		System.out.println(getNisHost("master"));
	}
	catch (Exception e) {
		System.out.println(e);
	}
	System.exit(0);
    }

    //
    // Get the local hostname
    // Return an empty string if we don't find one.
    //
    public synchronized static String getLocalHostName()
	throws Exception
    {
	Debug.message("SVR: Host.getLocalHostName()");

	String cmd = "/usr/bin/hostname";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);

	if (syscmd.getExitValue() != 0) {
		String err = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(err);
	}
	String o = syscmd.getOutput();
	syscmd = null;

	if (o == null)
		return (new String(""));
	return (new String(o));
    }

    //
    // Get the domainname
    // Return an empty string if we don't find one.
    //
    public synchronized static String getDomainName()
	throws Exception
    {
	Debug.message("SVR: Host.getDomainName()");

	String cmd = "/usr/bin/domainname";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String err = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(err);
	}

	String o = syscmd.getOutput();
	syscmd = null;

	if (o == null)
		return (new String(""));
	return (new String(o));
    }

    public synchronized static void pingHost(String host)
	throws Exception
    {
	int exitvalue;

	Debug.message("SVR: Host.pingHost()");

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/sbin/ping " + host);
	exitvalue = syscmd.getExitValue();
	syscmd = null;

	if (exitvalue != 0) {
		String err = syscmd.getError();
		throw new pmHostNotPingableException(err);
	}
    }

    public synchronized static String getNisMaster()
	throws Exception
    {
	return (getNisHost("master"));
    }

    //
    // Look for the nis server.
    // If we are looking for the master server first try
    // the printers.conf.byname map. If that fails
    // look for passwd.
    //
    public synchronized static String getNisHost(String type)
	throws Exception
    {
	Debug.message("SVR: Host.getNisHost() " + type);

	SysCommand syscmd = null;
	String cmd = null;
	int exitvalue = 0;

	if (type.equals("master")) {
		cmd = "/usr/bin/ypwhich -m printers.conf.byname";
	} else {
		cmd = "/usr/bin/ypwhich";
	}
	syscmd = new SysCommand();
	syscmd.exec(cmd);
	exitvalue = syscmd.getExitValue();
	if ((exitvalue != 0) && (type.equals("master"))) {
		Debug.message("SVR: printers.conf NIS host not found.");
		Debug.message("SVR: Looking for NIS passwd host.");
		cmd = "/usr/bin/ypwhich -m passwd";

		syscmd = new SysCommand();
		syscmd.exec(cmd);
		exitvalue = syscmd.getExitValue();
	}
	if (exitvalue != 0) {
		Debug.error("SVR: NIS server could not be found");
		String err = syscmd.getError();
		syscmd = null;
		throw new pmNSNotConfiguredException(err);
	}

	String o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		throw new pmCmdFailedException(syscmd.getError());
	}
	o = o.trim();
	return (new String(o));
    }

    /*
     * Return the name of the first server listed by ldapclient
     */
    public synchronized static String getLDAPMaster()
	throws Exception
    {
	SysCommand syscmd = null;
	String cmd = null;
	int exitvalue = 0;

	/* ldapclient will hang if we are not root. */
	if (!DoPrinterNS.isRoot()) {
		Debug.error("SVR: Not root. Can't determine LDAP master.");
		return null;
	}

	cmd = "/usr/sbin/ldapclient list";
	syscmd = new SysCommand();
	syscmd.exec(cmd);
	exitvalue = syscmd.getExitValue();

	if (exitvalue != 0) {
		Debug.error("SVR: ldapclient failed.");
		Debug.error("SVR: " + syscmd.getError());
		syscmd = null;
		return null;
	}
	String o = syscmd.getOutput();
	syscmd = null;

	String master = DoPrinterView.getToken(o + "\n", "NS_LDAP_SERVERS=");
	if (master == null) {
		Debug.error("SVR: ldapclient did not return NS_LDAP_SERVERS.");
		syscmd = null;
		return null;
	}

	/* Extract the first address from the NS_LDAP_SERVERS list */

	for (int i = 0; i < master.length(); i++) {
		if ((master.charAt(i) == ',') ||
		    (master.charAt(i) == ' ') ||
		    (master.charAt(i) == '\t')) {
			master = master.substring(0, i);
			break;
		}
	}
	master = master.trim();

	return (new String(master));
    }

    /*
     * Get a default admin DN.
     */
    public synchronized static String getDefaultAdminDN()
	throws Exception
    {
	SysCommand syscmd = null;
	String cmd = null;
	int exitvalue = 0;

	try {
		String master = getLDAPMaster();
		cmd = "/usr/bin/ldapsearch -h " + master +
		    " -b o=NetScapeRoot o=NetscapeRoot";
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		exitvalue = syscmd.getExitValue();
		if (exitvalue == 0) {
			String on =  syscmd.getOutput();
			syscmd = null;
			if (on != null) {
				if (on.indexOf("NetscapeRoot") != -1) {
					return ("cn=Directory Manager");
				}
			}
		}
		syscmd = null;
	}
	catch (Exception e) {
		Debug.message("SVR: ldapsearch for NSDS failed. Continuing");
	}

	cmd = "/usr/bin/ldaplist -d printers";
	syscmd = new SysCommand();
	syscmd.exec(cmd);
	exitvalue = syscmd.getExitValue();

	if (exitvalue != 0) {
		Debug.error("SVR: ldaplist printers failed.");
		Debug.error("SVR: " + syscmd.getError());
		syscmd = null;
		return null;
	}
	String o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		return null;
	}

	String dn = DoPrinterView.getToken(o + "\n", "ou=printers,");
	if (dn == null) {
		return null;
	}
	dn = "cn=admin," + dn;
	dn = dn.trim();

	return (new String(dn));
    }

    //
    // Check to see if a name service is configured
    //
    public synchronized static void isNSConfigured(String ns)
	throws Exception
    {
	Debug.message("SVR: Host.isNSConfigured() " + ns);

	int exitvalue;
	String cmd = null;
	String err = null;
	SysCommand syscmd = null;

	if (ns.equals("system")) {
		return;
	} else if (ns.equals("nis")) {
		cmd = "/usr/bin/ypwhich";
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		exitvalue = syscmd.getExitValue();
		err = syscmd.getError();
		syscmd = null;

		if (exitvalue != 0) {
			throw new pmNSNotConfiguredException(err);
		}

		cmd = "/usr/bin/ypcat cred";
		syscmd = new SysCommand();
		syscmd.exec(cmd);
		exitvalue = syscmd.getExitValue();
		syscmd = null;
		if (exitvalue == 0) {
			Debug.warning(
			    "SVR: Unable to update this configuration.");
			throw new pmNSNotConfiguredException();
		}
	} else if (ns.equals("ldap")) {
		/*
		 * Check if the ldap-client is configured by first checking
		 * if the config file exists and then invoking ldaplist
		 * Note: we need to check if the config file exists before
		 * invoking ldaplist so that we don't get its error message
		 */

		File ldapConfig = new File("/var/ldap/ldap_client_file");
		if (ldapConfig.isFile()) {
			// Config file exists

			cmd = "/usr/bin/ldaplist -d printers";
			syscmd = new SysCommand();
			syscmd.exec(cmd);
			exitvalue = syscmd.getExitValue();
			syscmd = null;

			if (exitvalue != 0) {
				throw new pmNSNotConfiguredException();
			}
		} else {
			throw new pmNSNotConfiguredException();
		}
	} else {
		throw new pmInternalErrorException(
		    "Unkown name service " + ns);
	}
    }
}
