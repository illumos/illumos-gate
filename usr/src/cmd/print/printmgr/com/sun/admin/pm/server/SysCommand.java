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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SysCommand
 * Execute a command and capture stdout/stderr.
 *
 */

package com.sun.admin.pm.server;

import java.io.*;

public class SysCommand
{

    private Process p = null;
    private String out = null;
    private String err = null;
    private int status = 0;

    public static void main(String[] args) {
	SysCommand syscmd = new SysCommand();
	String cmd = "ypcat hosts";
	String o = "";
	try {
		syscmd.exec(cmd);
	}
	catch (Exception e) {
		System.out.println(e);
	}
	o = syscmd.getOutput();
	System.out.println(o);
    }

    /*
     * Execute a system command.
     * @param String cmd The command to be executed.
     */
    public void exec(String cmd) throws Exception
    {
	if (cmd == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null command");
	}

	debug_log(cmd);

	p = Runtime.getRuntime().exec(cmd);
	if (p == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null process");
	}
	out = readOut();
	err = readErr();
	p.waitFor();
	status = getStatus();
	dispose();
    }

    public void exec(String[] cmd) throws Exception
    {
	if (cmd == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null command");
	}

	// Trim command arrays with nulls at the end.
	int i;
	for (i = 0; i < cmd.length; i++) {
		if (cmd[i] == null) {
			break;
		}
	}
	if (i != cmd.length) {
		String[] newcmd = new String[i];

		for (i = 0; i < newcmd.length; i++) {
			newcmd[i] = cmd[i];
		}
		debug_log(PrinterDebug.arr_to_str(newcmd));
		p = Runtime.getRuntime().exec(newcmd);
	} else {
		debug_log(PrinterDebug.arr_to_str(cmd));
		p = Runtime.getRuntime().exec(cmd);
	}
	if (p == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null process");
	}
	out = readOut();
	err = readErr();
	p.waitFor();
	status = getStatus();
	dispose();
    }


    public void exec(String cmd, String locale) throws Exception
    {
	if (cmd == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null command");
	}

	debug_log(locale + "; " + cmd);

	String [] envp = new String[1];
	envp[0] = locale;
	p = Runtime.getRuntime().exec(cmd, envp);
	if (p == null) {
		throw new pmInternalErrorException(
		    "SysCommand.exec(): null process");
	}
	out = readOut();
	err = readErr();
	p.waitFor();
	status = getStatus();
	dispose();
    }

    public String getOutput() {
	if (out == null)
		return (null);
	return (new String(out));
    }
    public String getError() {
	if (err == null)
		return (null);
	return (new String(err));
    }
    public int getExitValue() {
	return (status);
    }


    private String readOut() throws Exception
    {
	String result = null;
	String line = null;
	BufferedReader out = null;

	out = new BufferedReader(
	    new InputStreamReader(p.getInputStream()));
	while ((line = out.readLine()) != null) {
		if (result == null)
			result = line;
		else
			result = result.concat("\n" + line);
	}
	return (result);
    }

    private String readErr() throws Exception
    {
	String errstr = null;
	String line = null;
	BufferedReader err = null;

	err = new BufferedReader(
	    new InputStreamReader(p.getErrorStream()));
	while ((line = err.readLine()) != null) {
		if (errstr == null) {
			errstr = line;
		} else {
			errstr = errstr.concat("\n" + line);
		}
	}
	return (errstr);
    }

    private int getStatus() throws Exception
    {
	return (p.exitValue());
    }

    /*
     * Clean up opened file descriptors.
     */
    private void dispose() {

	try {
		p.getInputStream().close();
		p.getOutputStream().close();
		p.getErrorStream().close();
		p.destroy();
	}
	catch (Exception e) {
		Debug.message("SVR:" + e.getMessage());
	}
    }

    /*
     * Log all commands as is except lpset with a password.
     */
    private void debug_log(String cmd)
    {
	if ((cmd.indexOf("lpset") != -1) &&
	    (cmd.indexOf(" -w ") != -1)) {
		String clean = "";
		int i = cmd.indexOf(" -w ");
		int j = 0;

		try {
			i += 4;
			clean = cmd.substring(0, i);
			clean = clean.concat("**** ");
			while (cmd.charAt(i) != ' ') {
				i++;
			}
		} catch (Exception e) {
			Debug.message("SVR: lpset command with a passwd.");
			return;
		}

		clean = clean.concat(cmd.substring(i, cmd.length()));
		Debug.message("SVR: " + clean);

	} else {
		Debug.message("SVR: " + cmd);
	}
    }
}
