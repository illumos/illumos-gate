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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SRMDebug.java
 */


package com.sun.wbem.solarisprovider.srm;

import java.io.*;
import java.util.*;
import java.text.*;
import java.sql.Time;

/**
 * This class is a COPY of the com.sun.wbem.client.Debug class. It is
 * slightly modified for the srm package requirements.
 *
 * The Debug class provides the ability to write debug trace statements
 * to an output device; either stdout, stderr, or a file.  Tracing is
 * controlled by two perfprovider properties:
 *.p
 * ProviderDEBUGLEVEL  - Sets the level of detail of tracing statements
 * ProviderDEBUGDEVICE - Sets the output device: stdout, sdterr, file
 *.p
 * The trace level is a combination of detail level and optional
 * information to be included on each statement.  The level is
 * a hexadecimal value from zero to 0xff:
 * bits 7 6 5 4  3 2 1 0
 *      ^ ^ ^ ^  ^ ^ ^ ^----- - provider method calls
 *      | | | |  | | +------- - provider method return values
 *      | | | |  | +--------- - rds command interface
 *      | | | |  +----------- - rds data flow
 *      | | | |
 *      | | | +------------- - thread synchronization
 *      | | +--------------- - unused
 *      | +----------------- - unused
 *      +------------------- - unused
 *
 * Optional information is
 * controlled by adding one or more modifiers to the level number,
 * including "t" to include a time stamp, "m" to include the class
 * and method name writing the trace statement, and "p" to include
 * the thread identifier.  Thus, a value for ProviderDEBUGLEVEL
 * might appear as
 *.p
 * ProviderDEBUGLEVEL =01tmp
 *.p
 * If the debug device is set to "file", a default trace filename
 * consisting of the name "wbem_client_mmdd_hhmm" is used for client
 * side tracing, and the name "perfprovider_mmdd_hhmm" is used for
 * server side tracing.  The mmdd_hhmm is the current time the trace
 * file is opened.  The default directory for the trace file is
 * /var/tmp.  The debug device may be set to a fully qualified
 * file path name, if desired.  If the client application cannot
 * write to the log file, tracing will be turned off.
 * 
 * @version 1.5  05/29/01
 * @author	Sun Microsystems, Inc.
 */
public final class SRMDebug {

    // =====================================================================
    //
    // Static define constant to control compilation of trace methods
    //
    // =====================================================================

    // If this flag is set to true, the trace method implementation code
    // will be active and tracing can be controlled through the runtime
    // wbem.debug.level system property.  If this flag is set to false,
    // the compiler should remove the method implementation, leaving an
    // empty method.  This should allow JIT compilers to inline these
    // methods, resulting in the debugging trace method call being
    // removed from the tracing code!

    // XXXX - Typically set to true for development phases, reset to
    // XXXX - false for shipped code.

    private static final boolean ON = true;

    // =====================================================================
    //
    // Private define constants
    //
    // =====================================================================

    private final static String TRACE_DIR = "/var/tmp";
    private final static String TRACE_STDERR_NAME = "stderr";
    private final static int TRACE_OFF = 0;
    private final static int TRACE_STDERR = 2;
    private final static int TRACE_FILE = 3;
    private final static int TRACE_RETRY = 5;

    // =====================================================================
    //
    // Private attributes
    //
    // =====================================================================

    // Private static attributes
    private static boolean trace_init = false;
    private static int trace_level = TRACE_OFF;
    private static boolean trace_time = false;
    private static boolean trace_method = false;
    private static boolean trace_thread = false;
    private static int trace_out = TRACE_STDERR;
    private static FileWriter trace_fw;
    private static BufferedWriter trace_bw;
    private static PrintWriter trace_pw;

    // =====================================================================
    //
    // Public static attributes
    //
    // =====================================================================

    static final int METHOD_CALL = 0x01;
    static final int METHOD_RETV = 0x02;
    static final int RDS_CMD_IFC = 0x04;
    static final int RDS_DATAFLW = 0x08;
    static final int THREAD_SYNC = 0x10;
    static final int UNUSED1 	 = 0x20;
    static final int UNUSED2 	 = 0x40;
    static final int UNUSED3 	 = 0x80;
    static final int TRACE_ALL 	 = 0xFF;

    // =====================================================================
    //
    // Public static methods
    //
    // =====================================================================

    /**
     * The traceOpen method initializes the client or server 
     * for debug tracing.  The level of tracing is specified as a hexadecimal
     * from zero (no tracing) to ff (most detailed tracing) with
     * optional characters to indicate additional message prefix informatino.
     * The trace file name argument can specify output to standard out,
     * standard error, or a specific log trace file name.  The management
     * client and management server will each specify a different trace
     * file name.  The trace file will be written to the local system's
     * /var/log directory.
     *
     * @param	level	    The debug trace level: {0|1|2|3} + t, m, p
     * @param	filename    The debug trace log file name, stdout, or stderr
     */
    public static final void traceOpen(String level, String filename) {

	if (SRMDebug.ON) {
	    openTrace(level, filename);
	}

    }

    /**
     * The isOn method returns true if debug tracing is configured
     * and the debug trace level is greater than zero (tracing is
     * enabled at some level).
     *
     * @return	True if some level of tracing is enabled
     */
    public static final boolean isOn() {

        if (SRMDebug.ON) {
	    if (trace_level > 0) {
		return (true);
	    }
	}
	return (false);

    }
    
    /**
     * The isOn method returns true if debug tracing is configured
     * and the debug trace level mask is equal to the level.
     *
     * @return	True if some level of tracing is enabled
     */
    public static final boolean isOn(int level) {

        if (SRMDebug.ON) {
	    if ((trace_level & level) != 0) {
		return (true);
	    }
	}
	return (false);

    }

    /**
     * This debug trace message method writes the message to the trace
     * log device if we are tracing at the level mask given by level.
     *
     * @param	message The debug trace message
     */
    public static final void trace(int level, String message) {

	if (SRMDebug.ON) {
	    if ((trace_level & level) != 0) {
		writeTrace(message);
	    }
	}

    }

    /**
     * This debug trace message method writes the message and an exception
     * stack trace to the log if we are tracing at level 1.
     *
     * @param	message	The debug trace message
     * @param	ex	The exception to trace back
     */
    public static final void trace1(String message, Throwable ex) {

	if (SRMDebug.ON) {
	    if (trace_level > 0) {
		writeTrace(message);
		if (ex != null) {
		    writeStackTrace(ex);
		}
	    }
	}

    }

    /**
     * This debug trace message method writes the message to the trace
     * log device if we are tracing at level 2.
     *
     * @param	message The debug trace message
     */
    public static final void trace2(String message) {

	if (SRMDebug.ON) {
	    if (trace_level > 1) {
		writeTrace(message);
	    }
	}

    }

    /**
     * This debug trace message method writes the message and an exception
     * stack trace to the log if we are tracing at level 2.
     *
     * @param	message	The debug trace message
     * @param	ex	The exception to trace back
     */
    public static final void trace2(String message, Throwable ex) {

	if (SRMDebug.ON) {
	    if (trace_level > 1) {
		writeTrace(message);
		if (ex != null) {
		    writeStackTrace(ex);
		}
	    }
	}

    }

    /**
     * This debug trace message method writes the message to the trace
     * log device if we are tracing at level 3.
     *
     * @param	message The debug trace message
     */
    public static final void trace3(String message) {

	if (SRMDebug.ON) {
	    if (trace_level > 2) {
		writeTrace(message);
	    }
	}

    }

    /**
     * This debug trace message method writes the message and an exception
     * stack trace to the log if we are tracing at level 3.
     *
     * @param	message	The debug trace message
     * @param	ex	The exception to trace back
     */
    public static final void trace3(String message, Throwable ex) {

	if (SRMDebug.ON) {
	    if (trace_level > 2) {
		writeTrace(message);
		if (ex != null) {
		    writeStackTrace(ex);
		}
	    }
	}

    }

    // ********************************************************************
    //
    // Private methods
    //
    // *******************************************************************

    // Internal method to open the trace log file
    private static void openTrace(String level, String filename) {

	String trace_file = null;
	String trace_sufx = null;
	int i;

	if (trace_init)
	    return;

	// Get the trace level and any optional flags
	trace_level = TRACE_OFF;
	trace_time = false;
	trace_method = false;
	trace_thread = false;
	if (level != null) {
	    try {
	    	trace_level = Integer.parseInt(level.substring(0, 2), 16);
	    } catch (Exception ex) {
		trace_level = 0;
	    }
	    if (level.indexOf('t') > 0) {
		trace_time = true;
	    }
	    if (level.indexOf('m') > 0) {
		trace_method = true;
	    }
	    if (level.indexOf('p') > 0) {
		trace_thread = true;
	    }
	}

	// If tracing turned off at runtime, just return.
	if (trace_level == 0) {
	    return;
	}

	// Set the output device for tracing.  Must be stdout, stderr,
	// or a file name.  If invalid, set tracing off silently!
	if ((filename != null) && (filename.trim().length() != 0)) {
    	    if (filename.equals(TRACE_STDERR_NAME))
		trace_out = TRACE_STDERR;
	    else {
		trace_out = TRACE_FILE;
		trace_file = filename.trim();
	    }
	} else {
	    // Invalid or null trace file name; default to stderr.
	    trace_level = TRACE_STDERR;
	}

	// If tracing to a file, form the fully qualified path name to the
	// file.  Trace file suffix is .MMDD_HHMM from current time.
	// Trace file will be opened in the system temp directory.
	// If it already exists, add a numeric suffix until not found.
	if ((trace_out == TRACE_FILE) && (trace_level > 0)) {
	    if (trace_file.indexOf(File.separatorChar) < 0) {
		trace_file = getLogDir() + File.separator + trace_file;
	    }
	    SimpleDateFormat sdf = new SimpleDateFormat("MMdd_HHmm");
	    trace_sufx = "_" + sdf.format(new Date());
	    trace_file = trace_file +  trace_sufx;
	    String name = trace_file;
	    for (i = 1; i < TRACE_RETRY; i++) {
		try {
		    File fd1 = new File(name);
		    if (!(fd1.exists()))
			break;
		    name = trace_file + "_" + i;
		} catch (Exception ex) {
		    // Eat exceptions
		}
	    }				    // End of for
	    if (i < TRACE_RETRY) {
		try {
		    trace_fw = new FileWriter(name);
		    trace_bw = new BufferedWriter(trace_fw);
		    trace_pw = new PrintWriter(trace_bw, true);
		} catch (Exception ex) {
		    // Eat exceptions and turn off tracing if errors
		    trace_level = 0;
		}
	    } else			    // File already exists!
		trace_level = 0;
	}

	// Indicate we have initialized tracing
	trace_init = true;

    }

    // Internal method to write an exception stack trace to the log.

    private static void writeStackTrace(Throwable ex) {

	try {
	    if (trace_out == TRACE_FILE) {
		ex.printStackTrace(trace_pw);
	    } else if (trace_out == TRACE_STDERR) {
		ex.printStackTrace(System.err);
	    }
	} catch (Exception x) {
	    // Eat exceptions
	}

    }

    // Return the trace log file directory

    private static String getLogDir() {

	// For now, this is fixed.  Need to make is smarter when
	// running client on a Wintel machine.
	return (TRACE_DIR);

    }

    // Return the class name and method name that called the trace method.

    private static String getClassMethod() {

	String line;
	String clm;

	clm = null;
	try {
	    InputStream is = getStackStream();
	    BufferedReader br = new BufferedReader(new InputStreamReader(is));
	    br.readLine();		// Skip top five lines...
	    br.readLine();
	    br.readLine();
	    br.readLine();
	    br.readLine();
	    line = br.readLine();	// This should be caller from stack
	    clm = getCaller(line);	// Pull out class and method name
	    br.close();
	} catch (Exception ex) {
	    clm = "??:??";		// If any errors, don't know names
	}

	return (clm);
    }

    // Write trace message.  Ignore exceptions...

    private static synchronized void writeTrace(String msg) {

	String trace_msg = "";
	if (trace_time) {
	    Time tim = new Time(System.currentTimeMillis());
	    trace_msg = tim.toString() + " | ";
	}
	if (trace_thread) {
	    Thread th = Thread.currentThread();
	    trace_msg = trace_msg + th.getName() + " | ";
	}
	if (trace_method) {
	    trace_msg = trace_msg + getClassMethod() + " | ";
	}
	trace_msg = trace_msg + msg;
	try {
	    if (trace_out == TRACE_FILE) {
		trace_pw.println(trace_msg);
	    } else if (trace_out == TRACE_STDERR) {
		System.err.println(trace_msg);
	    }
	} catch (Exception ex) {
	    // Eat exceptions
	}

    }

    // Get stack trace for determining calling class and method

    private static InputStream getStackStream() {

	ByteArrayInputStream is = null;
	ByteArrayOutputStream os = new ByteArrayOutputStream();

	try {
	    PrintWriter pw = new PrintWriter(os);
	    new Exception().printStackTrace(pw);
	    pw.close();
	    is = new ByteArrayInputStream(os.toByteArray());
	} catch (Exception ex) {
	    is = null;
	}

	return (is);

    }

    // Get class name and method name from stack trace line

    private static String getCaller(String line) {

	String str, mth, cls;
	int i;

	str = line;
	i = line.indexOf('(');
	if (i > 0)
	    str = line.substring(0, i);
	i = str.indexOf("at");
	if (i > 0)
	    str = str.substring(i+3);
	i = str.lastIndexOf('.');
	if (i > 0) {
	    mth = str.substring(i+1);
	    str = str.substring(0, i);
	    i = str.lastIndexOf('.');
	    if (i > 0)
		cls = str.substring(i+1);
	    else
		cls = str;
	    str = cls + ":" + mth;
	}

	return (str);
    }

}
