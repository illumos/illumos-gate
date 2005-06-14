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
 * Copyright (c) 1999,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

package com.sun.slp;

import java.io.*;

/**
 * A logging class which writes to UNIX syslog. This class can be dynamically
 * loaded by SLPConfig and used as the log object by the writeLog and
 * writeLogLine methods. Note that we need to use JNI here to call the
 * native syslog. This is because syslog can be listening on any port
 * mapped to 'syslog' in the services table, but Java provides no way to
 * query this mapping.
 *
 * This class does not actually write anything until the flush() method
 * in invoked; this will write the concatenation of all messages
 * passed to the write() method since the last invokation of flush().
 *
 * The actual logging class used can be controlled via the
 * sun.net.slp.loggerClass property.
 *
 * See also the SLPLog (in slpd.java) and StderrLog classes.
 */

class Syslog extends Writer {

    private StringBuffer buf;

    public Syslog() {
	buf = new StringBuffer();

	// can't just get SLPConfig; causes stack recursion
	tracingOn = Boolean.getBoolean("sun.net.slp.traceALL") ||
	    Boolean.getBoolean("net.slp.traceReg") ||
	    Boolean.getBoolean("net.slp.traceMsg") ||
	    Boolean.getBoolean("net.slp.traceDrop") ||
	    Boolean.getBoolean("net.slp.traceDATraffic");
    }

    public void write(char[] cbuf, int off, int len) throws IOException {
	buf.append(cbuf, off, len);
    }

    public void flush() {
	int priority;
	if (tracingOn) {
	    priority = 6;	// LOG_INFO
	} else {
	    priority = 2;	// LOG_CRIT
	}

	syslog(priority, buf.toString());
	buf = new StringBuffer();
    }

    public void close() {
    }

    private native void syslog(int priority, String message);

    // The JNI implementation is in libslp.so.
    static {
	System.load("/usr/lib/libslp.so");
    }

    private boolean tracingOn;
}
