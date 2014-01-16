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
 * DoPrinterUtil class
 * Worker utility class.
 */

package com.sun.admin.pm.server;

import java.io.*;
import java.util.*;

public class  DoPrinterUtil {

    public static String getDefault(String ns) throws Exception
    {
	Debug.message("SVR: DoPrinterUtil.getDefault()");
	Debug.message("SVR: name service equals " + ns);

	String o = null;
	String cmd = "/usr/bin/lpget -n " + ns + " _default";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		return (null);
	}
	int i = o.indexOf("use=");
	if (i == -1) {
		return (null);
	}
	o = o.substring(i);
	String dflt = DoPrinterView.getToken(o + "\n", "use=");

	Debug.message("SVR: default is " + dflt);
	return (new String(dflt));
    }

    public static String[] getDevices() throws Exception
    {
	Debug.message("SVR: DoPrinterUtil.getDevices()");

	int i = 0;
	String dev = "";
	String devices = "";

	String serial_possibilities[] = {"a", "b", "c", "d",
		"e", "f", "g", "h", "i", "j", "k", "l", "m",
		"n", "o", "p", "q", "r", "s", "t", "u", "v",
		"w", "x", "y", "z"};

	String cmd = "/usr/bin/find /dev -print";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}

	String o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		return (null);
	}
	o = o.concat("\n");

	for (i = 0; i < serial_possibilities.length; i++) {
		dev = "/dev/term/" + serial_possibilities[i] + "\n";
		if (o.indexOf(dev) != -1) {
			devices = devices.concat(" " + dev + " ");
		}
	}
	// sparc bpp parallel ports
	for (i = 0; i < 100; i++) {
		dev = "/dev/bpp" + i + "\n";
		if (o.indexOf(dev) != -1) {
			devices = devices.concat(" " + dev + " ");
		}
	}
	// sparc ecpp parallel ports
	for (i = 0; i < 100; i++) {
		dev = "/dev/ecpp" + i + "\n";
		if (o.indexOf(dev) != -1) {
			devices = devices.concat(" " + dev + " ");
		}
	}
	// intel parallel ports
	for (i = 0; i < 100; i++) {
		dev = "/dev/lp" + i + "\n";
		if (o.indexOf(dev) != -1) {
			devices = devices.concat(" " + dev + " ");
		}
	}

	// USB
	for (i = 0; i < 100; i++) {
		dev = "/dev/printers/" + i + "\n";
		if (o.indexOf(dev) != -1) {
			devices = devices.concat(" " + dev + " ");
		}
	}

	// SunPics
	dev = "/dev/lpvi\n";
	if (o.indexOf(dev) != -1) {
		devices = devices.concat(" " + dev + " ");
	}

	o = null;

	if (devices.equals("")) {
		return (null);
	}

	String ret[];
	StringTokenizer st = new StringTokenizer(devices);
	if (st.countTokens() == 0) {
		return (null);
	} else {
		ret = new String[st.countTokens()];
		for (i = 0; st.hasMoreTokens(); i++) {
			ret[i] = st.nextToken();
		}
	}
	return (ret);
    }

    public static String[] getMakes() throws Exception
    {
	int i;

	Debug.message("SVR: DoPrinterUtil.getMakes()");

	String cmd = "/usr/lib/lp/bin/getmakes";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	String makes = syscmd.getOutput();

	String ret[];
	StringTokenizer st = new StringTokenizer(makes);
	if (st.countTokens() == 0) {
		return (null);
	} else {
		ret = new String[st.countTokens()];
		for (i = 0; st.hasMoreTokens(); i++) {
			ret[i] = st.nextToken();

		}
	}
	return (ret);

    }
    public static String[] getModels(String make) throws Exception
    {
	int i;
	String ret[];

	Debug.message("SVR:getModels()");

	if (make == null) {
		Debug.message("SVR:getModels: make is null");
		return (null);
	}
	// Make call for models for this make
	String cmd = "/usr/lib/lp/bin/getmodels " +  make;
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	String models = syscmd.getOutput();

	if (models != null) {
	    StringTokenizer st = new StringTokenizer(models, "\n");
	    if (st.countTokens() == 0) {
		Debug.message("SVR:String tokenizer count is zero");
		return (null);
	    } else {
		ret = new String[st.countTokens()];
		for (i = 0; st.hasMoreTokens(); i++) {
			ret[i] = st.nextToken();

		}
	    }
	    return (ret);
	} else
		return (null);
    }

    public static String[] getPPDs(String make, String model) throws Exception
    {
	int i;
	String ret[];
	ret = new String[2];
	if ((make == null) || (model == null)) {
		return null;
	}
	// get ppd files for this make/model
	String cmd = "/usr/lib/lp/bin/getppds " + make + " " +  model;
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	String ppds = syscmd.getOutput();
	StringTokenizer st = new StringTokenizer(ppds, "\n");
	if (st.countTokens() == 0) {
		return (null);
	} else {
		ret = new String[st.countTokens()];
		for (i = 0; st.hasMoreTokens(); i++) {
			ret[i] = st.nextToken();

		}
	}
	return (ret);
    }

    public static String[] getMakeModelNick(String ppdfilename) throws Exception
    {
	int i;
	String ret[] = null;
	if (ppdfilename == null) {
		return (null);
	}
	// get ppd files for this make/model
	String cmd = "/usr/lib/lp/bin/ppdfilename2mmp " + ppdfilename;
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	String mmp  = syscmd.getOutput();

	if (mmp != null) {
		ret = new String[2];

	    StringTokenizer st = new StringTokenizer(mmp, "\n");
	    if (st.countTokens() == 0) {
		    return (null);
	    } else {
		    ret = new String[st.countTokens()];
		    for (i = 0; st.hasMoreTokens(); i++) {
			    ret[i] = st.nextToken();

		    }
	    }
	}
	return (ret);
    }

    public static String getPPDFile(
		String make, String model, String ppd) throws Exception
    {
	int i;
	String ret[];
	ret = new String[2];
	if (ppd == null)  {
		return (null);
	}
	// get ppd path/filename for this ppd
	String cmd = "/usr/lib/lp/bin/getppdfile " +
		make + ":" + " " + model + ":" +  " " +  ppd + ":";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	String ppdfile = syscmd.getOutput();

	return (ppdfile);
    }


    public static String[] getProbe(String device)
    {
        int i;
        String pmake = null;
        String pmodel = null;
        String tokens[] = null;
        String ret[];
        ret = new String[2];

        if (device == null)
                return (null);

        Debug.message("SVR: DoPrinterUtil.getProbe()");

        // Get Manufacturer and Model for printer in this port
        String cmd = "/usr/lib/lp/bin/printer-info -M -m " + device;
        SysCommand syscmd = new SysCommand();
        try {
                syscmd.exec(cmd);
        } catch (Exception e) {
                System.out.println(e);
        }
        if (syscmd.getExitValue() != 0) {
                String errstr = syscmd.getError();
                syscmd = null;
                return (null);
        }

        String mm = syscmd.getOutput();
        if (mm != null) {
                int numtokens;
                StringTokenizer st = new StringTokenizer(mm, ":" + "\n");
                if (st.countTokens() == 0) {
                        return (null);
                } else {
                        numtokens = st.countTokens();
                        tokens = new String[st.countTokens()];
                        for (i = 0; st.hasMoreTokens(); i++) {
                                tokens[i] = st.nextToken();
                        }
                }
                for (i = 0; i < numtokens; i++) {
                        if ((tokens[i].trim()).equals("Manufacturer")) {
                                pmake =  new String(tokens[i + 1].trim());
                        } else { if ((tokens[i].trim()).equals("Model"))
                                pmodel =  new String(tokens[i + 1].trim());
                        }
                }

                if (pmake != null)
                        ret[0] = pmake;
                if (pmodel != null)
                        ret[1] = pmodel;

                return (ret);
        }
        return (null);

    }

    public static boolean isMakeModel(
        String make,
        String model)
    {
        int exitvalue;

        Debug.message("SVR: DoPrinterUtil.isMakeModel() " + make + " " + model);

        SysCommand syscmd = new SysCommand();
        // syscmd.exec("/usr/bin/lpget -n " + ns + " " + name);
        exitvalue = syscmd.getExitValue();
        syscmd = null;
        if (exitvalue == 0) {
                return (true);
        }
        return (false);
    }


    public static String[] getList(String nsarg)
	throws Exception
    {
	Debug.message("SVR: DoPrinterUtil.getList()");

	int i = 0;
	int j = 0;
	int listi = 0;

	String cmd = null;
	String printername = "";
	String printserver = "";
	String comment = "";
	String nameservice;
	String list[];

	String o = null;
	cmd = "/usr/bin/lpget -n " + nsarg + " list";
	SysCommand syscmd = new SysCommand();
	syscmd.exec(cmd);
	if (syscmd.getExitValue() != 0) {
		String errstr = syscmd.getError();
		syscmd = null;
		throw new pmCmdFailedException(errstr);
	}
	o = syscmd.getOutput();
	syscmd = null;

	if (o == null) {
		return (null);
	}

	// Count entries
	int index = 0;
	while ((index = o.indexOf("bsdaddr=", index)) != -1) {
		index = index + 8;
		i++;
	}
	if (i <= 0)
		return (null);

	list = new String [i*3];

	int colon = 0;
	int nextcolon = 0;
	while ((colon = o.indexOf(":\n", colon + 1)) != -1) {
		nextcolon = o.indexOf(":\n", colon + 1);
		if (nextcolon == -1)
			nextcolon = o.length();
		// Extract printername
		i = colon;
		while ((o.charAt(i) != '\n') && (i != 0)) {
			i--;
		}
		if (i == 0)
			printername = o.substring(i, colon);
		else
			printername = o.substring(i + 1, colon);

		// Skip _all and _default keywords
		if (printername.equals("_all")) {
			continue;
		}
		if (printername.equals("_default")) {
			continue;
		}

		// Extract servername
		i = o.indexOf("bsdaddr=", colon);
		if ((i != -1) && (i < nextcolon)) {
			j = o.indexOf(",", i);
			if (j != -1)
				printserver = o.substring(i + 8, j);
		}
		// Skip entries without a server.
		if (printserver.equals("")) {
			Debug.warning(
			    "SVR: printer does not have a server: "
			    + printername);
			continue;
		}

		// Extract description
		i = o.indexOf("description=", colon);
		if ((i != -1) && (i < nextcolon)) {
			j = i;
			while (j < o.length()) {
				if (o.charAt(j) == '\n')
					break;
				j++;
			}
			comment = o.substring(i + 12, j);
		}

		list[listi++] = printername;
		list[listi++] = printserver;
		list[listi++] = comment;
		printername = "";
		printserver = "";
		comment = "";
	}
	return (list);
    }

    public static boolean exists(
	String name,
	String ns) throws Exception
    {
	int exitvalue;

	Debug.message("SVR: DoPrinterUtil.exists() " + ns);

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/lpget -n " + ns + " " + name);
	exitvalue = syscmd.getExitValue();
	syscmd = null;
	if (exitvalue == 0) {
		return (true);
	}
	return (false);
    }

    public static boolean isLocal(
	String pn) throws Exception
    {
	int exitvalue;

	Debug.message("SVR: DoPrinterUtil.isLocal()");

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/test -d /etc/lp/printers/" + pn);
	exitvalue = syscmd.getExitValue();
	syscmd = null;
	if (exitvalue != 0) {
		return (false);
	}
	return (true);
    }

    public static boolean isLocalhost(
	String queue) throws Exception
    {
	int exitvalue;
	String o = null;

	Debug.message("SVR: DoPrinterUtil.isLocalhost():queue " + queue);

	SysCommand syscmd = new SysCommand();
	syscmd.exec("/usr/bin/grep " + queue +  " /etc/printers.conf");
	exitvalue = syscmd.getExitValue();
	if (exitvalue != 0) {
	    Debug.message(
		"SVR:DoPrinterUtil:isLocalhost:failed:queue: " + queue);
	    return (false);
	}
	o = syscmd.getOutput();
	syscmd = null;
	Debug.message("SVR:DoPrinterUtil.java:isLocalhost: output: " + o);
	if (o.indexOf("localhost") != -1)
		return (true);
	else
		return (false);
    }
}
