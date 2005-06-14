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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.dhcpbatch;

import java.io.*;
import java.text.MessageFormat;

import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.cli.common.DhcpCliPrint;
import com.sun.dhcpmgr.cli.common.DhcpCliProgram;
import com.sun.dhcpmgr.cli.common.DhcpCliFunction;

/**
 * This class represents the entry point to the DHCP CLI batch
 * administration.
 */
public class DhcpBatch
    extends DhcpCliProgram {

    /**
     * The program signature.
     */
    public static final String SIGNATURE = "dhcpbatch: ";

    /**
     * The source of the batch input. Either a fullpath to an
     * input file or null if standard input is the source.
     */
    String inputSource = null;

    /**
     * Flag indicating whether or not the batch processing
     * should be verbose.
     */
    boolean verbose = false;

    /**
     * The constructor used by the DHCP CLIs.
     * @param inputSource a filepath or null if STDIN is to be used.
     */
    public DhcpBatch(String inputSource) {
	this();
	this.inputSource = inputSource;
    } // constructor

    /**
     * The easy constructor that does nothing for now.
     */
    public DhcpBatch() {
    } // constructor

    /**
     * Required by DhcpCliProgram.
     * @return null
     */
    public String getManPage() {
	return null;
    }

    /**
     * Returns a localized string for this function
     * @param key the resource bundle string identifier
     * @return string from resource bundle.
     */
    public String getString(String key) {
	return ResourceStrings.getString(key);
    } // getString

    /**
     * Sets the inputSource value.
     * @param inputSource the input source.
     */
    public void setInputSource(String inputSource) {
	this.inputSource = inputSource;
    } // setInputSource

    /**
     * Sets the verbose value.
     * @param value the new value for the verbose attribute.
     */
    public void setVerbose(boolean value) {
	verbose = value;
    } // setVerbose

    /**
     * Executes the batch.
     * @return return code as returned by batched program
     */
    public int execute() {

	int returnCode = SUCCESS;

	// By default read input from standard input.
	//
	InputStream in = System.in;

	// If an argument was was provided, then it must be the batch file.
	// Read input from the file rather than standard input.
	//
	if (inputSource != null) {
	    try {
		in = new FileInputStream(inputSource);
	    } catch (FileNotFoundException e) {
		Object [] arguments = new Object[1];
		arguments[0] = inputSource;
		printErrMessage(getString("dhcpbatch_file_not_found"),
		    arguments);
		return (CRITICAL);
	    } catch (Throwable e) {
		Object [] arguments = new Object[1];
		arguments[0] = inputSource;
		printErrMessage(getString("dhcpbatch_open_failed"), arguments);
		printErrMessage(DhcpCliFunction.getMessage(e));
		return (CRITICAL);
	    }
	}

	// Really just want to read lines at a time so, a BufferedReader
	// will do the trick.
	//
	BufferedReader bufferedIn =
	    new BufferedReader(new InputStreamReader(in));

	// Read a line at a time and exec the appropriate DHCP CLI command.
	//
	StringBuffer line = new StringBuffer(200);
	line.append("> ");
	DhcpCommand command = new DhcpCommand();
	for (boolean end = false; end != true; ) {
	    try {
		// Read a line. End of file seems to result in null line.
		//
		String input = bufferedIn.readLine();
		if (input == null) { 
		    // eof
		    end = true;
		    continue;
		} else if (input.length() == 0) {
		    // empty line
		} else if (input.charAt(0) == '#' && line.length() == 2) {
		    // comment
		    continue;
		} else {
		    line.append(input);
		    if (input.charAt(input.length() - 1) == '\\') {
			// continuation
			continue;
		    }
		}

		if (verbose) {
		    DhcpCliPrint.printMessage(line.toString());
		}
		command.init(line.substring(2));
		command.execute();
	    } catch (BridgeException e) {
		// Failed to process command; print message and continue on
		Object [] arguments = new Object[2];
		arguments[0] = line.substring(2);
		arguments[1] = DhcpCliFunction.getMessage(e);
		printErrMessage(getString("dhcpbatch_cmd_error"), arguments);
		returnCode = CRITICAL;
	    } catch (EOFException e) {
		// Don't ever seem to get this, but just in case.
		//
		end = true;
	    } catch (IOException e) {
		Object [] arguments = new Object[1];
		arguments[0] = inputSource;
		printErrMessage(getString("dhcpbatch_read_failed"), arguments);
		printErrMessage(DhcpCliFunction.getMessage(e));
		end = true;
		returnCode = CRITICAL;
	    } finally {
		// Reset buffer to process next command
		line.setLength(2);
	    }
	}

	// Close the stream. Ignore errors as we're exiting anyway.
	//
	try {
	    bufferedIn.close();
	} catch (IOException e) {
	    // Ignore it.
	}

	return (returnCode);

    } // execute

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public static void printErrMessage(String msg) {
	StringBuffer fullmsg = new StringBuffer(SIGNATURE);
	fullmsg.append(msg);
	DhcpCliPrint.printErrMessage(fullmsg.toString());
    } // printErrMessage

    /**
     * Prints an error message.
     * @param msg the message to print.
     */
    public static void printErrMessage(String msg, Object [] arguments) {
	StringBuffer fullmsg = new StringBuffer(SIGNATURE);
	fullmsg.append(msg);
        MessageFormat form = new MessageFormat(fullmsg.toString());
	DhcpCliPrint.printErrMessage(form.format(arguments));
    } // printErrMessage

    /**
     * The entry point for the program.
     * @param args the program arguments
     */
    public static void main(String[] args) {

	DhcpBatch dhcpbatch = new DhcpBatch();

	// Check usage.
	//
	String source = null;
	if (args.length == 1) {
	    source = args[0];
	} else if (args.length > 1) {
	    DhcpCliPrint.printErrMessage(
		dhcpbatch.getString("dhcpbatch_usage"));
	    return;
	}

	dhcpbatch.setInputSource(source);
	dhcpbatch.execute();

    } // main

} // DhcpBatch
